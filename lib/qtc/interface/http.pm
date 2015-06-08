#-----------------------------------------------------------------------------------
=pod

=head1 NAME

qtc::interface::http - is a sync interface for QTC net via http

=head1 SYNOPSIS

 use qtc::interface::http; 

 my $if=qtc::interface::http->new(
   path=>$path, 
   url=>$url,
   debug=>1, 
 ); 
 $if->dprint("Sync down $url\n"); 
 $if->sync("/out"); 
 $if->dprint("Sync up $url\n"); 
 $if->{use_digest}=1; 
 $if->sync_upload("/out"); 

=head1 DESCRIPTION

qtc::interface::http is used to sync qtc net message repositorys 
via qtc-if.cgi script. 

=cut
# this is the http part of the interface
package qtc::interface::http;
use Digest::SHA qw(sha256_hex); 
use LWP::UserAgent; 
use IO::Scalar; 
use Archive::Tar; 
use File::Basename; 
use Data::Dumper; 
use qtc::msg;
use qtc::misc;
use qtc::interface;
@ISA=("qtc::interface"); 

#-------------------------------------------------------
=pod

=head2 new(parameter=>"value", ...)

Object creator function, returns qtc::interface object

Parameter: 
 path=>$path_to_qtc_root,  # required if not $HOME/.qtc
 url=>$url,      # The URL to sync with 
 debug=>0 or 1,            # this is 0 if not set. 
 use_ts=>1 or 0 # default 1 , use timestamps for syncronisation
 ts_dir=>$directory   # this is the directory where the timestamps 
               # for the syncronisations to the last server are recorded
              # default is $path/.interface_http 
 use_digest=>1,0     # get all messages as digest (default 0) 
 use_digest_lst=>1,0   # get message list as digest... 
                       # default 1
 lwp=>$lwp_object,   # an optional lwp object

=cut
#-------------------------------------------------------
sub new { 
	my $obj=shift; 
	my %arg=(@_); 
	$obj=$obj->SUPER::new(%arg);

	$obj->{can_publish}=1; 
	$obj->{can_sync}=1; 
	
	# features
	if ( ! defined $obj->{use_ts} ) { $obj->{use_ts}=1; } 
	if ( ! $obj->{ts_dir} ) { 
		$obj->{ts_dir}=$obj->{path}."/.interface_http";
	} 
	if ( $obj->{use_ts} ) {
		qtc::misc->new->ensure_path($obj->{ts_dir}); 
	}
	if ( ! $obj->{use_digest_lst} ) { $obj->{use_digest_lst}=1; $obj->{use_digest}=0; }  
		# get all messages as digest, we only have this one server
	
	if ( ! $obj->{use_digest} ) { $obj->{use_digest}=0; }  
		# get all messages as digest, we only have this one server

	if ( ! $obj->{lwp} ) { $obj->{lwp}=LWP::UserAgent->new; }

	# the counter of downloaded messages is held within the object 
	# in case if sync dies 
	$obj->{message_count}=0; 

	if ( ! $obj->url ) {
		die "I need an url to connect to\n";
	} 

	return $obj; 
}

#-------------------------------------------------------
=pod

=head2 url()

returns objects url

=cut
#-------------------------------------------------------
sub url { my $obj=shift; return $obj->{url}; }


#-------------------------------------------------------
=pod

=head2 lwp()

returns objects lwp object

=cut
#-------------------------------------------------------
sub lwp { my $obj=shift; return $obj->{lwp}; }


#-------------------------------------------------------
=pod

=head2 publish_tar(@msgs)

This puts a bunch of messages into a tar archive and puts that 
tar up to the server. 

=cut
#-------------------------------------------------------
sub publish_tar {
	my $obj=shift; 
	my @msgs=@_; 

	my $tar=Archive::Tar->new(); 
	foreach my $msg (@msgs) {
		if ( ! $msg ) { die "I need a qtc::msg object here\n"; }
		$obj->dprint("add ".$msg->filename." to tar  \n"); 
		$tar->add_data($msg->filename, pack("H*", $msg->as_hex));
	}

	if ( $#msgs >= 0 ) {
		$obj->dprint("put tar data to ".$obj->url." lengh ".length($tar->write)." \n"); 
		my $res=$obj->lwp->put($obj->url, 
			"Content-Type"=>"application/x-tar",
			Content=>$tar->write,
		); 

		if ( ! $res->is_success ) { 
			#open(TAR, "> /tmp/upload.tar"); print TAR $tar->write; close TAR; 
			die "File Upload not succeeded\n"; 
		}
	}
}

#-------------------------------------------------------
=pod

=head2 publish(@msgs)

This puts a bunch of messages and uploads them to the 
server

=cut
#-------------------------------------------------------
sub publish {
	my $obj=shift; 
	my @msgs=@_; 

#	print STDERR Dumper(\@msgs); 

	foreach my $msg (@msgs) {

		if ( ! $msg ) { die "I need a qtc::msg object here\n"; }

		$obj->dprint("put ".$msg->filename."\n");
 
		my $res=$obj->lwp->put($obj->url, 
			"Content-Type"=>"application/octet-stream",
			Content=>pack("H*", $msg->as_hex),
		); 

		if ( ! $res->is_success ) { die "File Upload not succeeded\n"; }
	}
}

#-------------------------------------------------------
=pod

=head2 sync_upload($local_path, $remote_path)

This compares the File lists between the localpath and the remotepath 
and uploads the differences to the remote location. 

If the pathes are ommitted, defaults are used. 

=cut
#-------------------------------------------------------
sub sync_upload {
	my $obj=shift; 
	my $local_path=shift;  # the qtc path (/out /call/FOO/telegrams/new) goes in here as parameter
	my $remote_path=shift;  # the qtc path (/in /out /call/FOO/telegrams/new) goes in here as parameter
	if ( ! $local_path ) { $local_path="/out"; }
	if ( ! $remote_path ) { $remote_path="/in"; }

	my $urlpath=$obj->url.$remote_path; 
	my $tsfile;
	my @args;

	# TODO: This is duplicated here and in sync. 
	# the timestamp of the last call is stored in a file so only files newer than 
	# the TS may get listet but first, load the old info.... 
	my $ts=0; 
	my $local_ts=0; 
	if ( $obj->{use_ts} ) {
		$obj->dprint("We are using timestamps\n"); 
		$tsfile=$obj->{ts_dir}."/".sha256_hex($local_path." ".$urlpath); 
		
		if ( -e $tsfile ) {
			$obj->dprint("using time of last sync\n"); 
			open(READ, "< $tsfile") or die "up I cant open $tsfile for reading \n"; 
			while(<READ>){ ($ts, $local_ts)=split(" ", $_); }
			close READ; 
		}
		$obj->dprint("I will syncronize all messages newer than $ts remote and $local_ts local\n"); 
		push @args, "ts=$ts"; 
	}

	$obj->dprint("url: ".$urlpath."?".join("&", @args)."\n"); 
	my $res=$obj->lwp->get($urlpath."?".join("&", @args)); 

	if ( ! $res->is_success ) { die "up http get to $urlpath failed\n"; }

	my $newts=$res->filename; 
	$obj->dprint("downloaded new ts: ".$newts."\n"); 

	if ( $newts !~ /^\d+$/ ) {  die "up uups $newts should be numeric\n"; } 


	# work here 
	my $new_local_ts=time;
	my $upload_count=$obj->process_dir_upload($local_path, $res->decoded_content, $urlpath, $local_ts); 
	$obj->dprint("uploaded ".$upload_count." qtc messages\n"); 
	

	if ( ( $newts ) and ( $obj->{use_ts} ))  { 
		open(WRITE, "> $tsfile") or die "Cant open $tsfile to write back timestamp\n"; 
		print WRITE "$newts $new_local_ts" or die "Cant write into $tsfile\n"; 
		close WRITE or die "Cant close $tsfile \n"; 
	}
}

#-------------------------------------------------------
=pod

=head2 sync($remote_path)

This compares the File lists between the localpath and the remotepath 
and downloads the differences from the remote location. 

Path is mandatory here.... 

=cut
#-------------------------------------------------------
sub sync {
	my $obj=shift; 
	my $path=shift;  # the qtc path (/out /call/FOO/telegrams/new) goes in here as parameter
	
	#print STDERR $obj->{path}."/in\n";
	qtc::misc->new->ensure_path($obj->{path}."/in"); 

	my $urlpath=$obj->url.$path; 
	my $tsfile;
	$obj->{message_count}=0; 

	my @args;

	# the timestamp of the last call is stored in a file so only files newer than 
	# the TS may get listet but first, load the old info.... 
	if ( $obj->{use_ts} ) {
		$obj->dprint("We are using timestamps\n"); 
		my $ts=0; 
		$tsfile=$obj->{ts_dir}."/".sha256_hex($urlpath); 
		
		if ( -e $tsfile ) {
			$obj->dprint("using time of last sync\n"); 
			open(READ, "< $tsfile") or die "I cant open $tsfile for reading \n"; 
			while(<READ>){ $ts=$_; }
			close READ; 
		}
		$obj->dprint("I will syncronize all messages newer than $ts\n"); 
		push @args, "ts=$ts"; 
	}

	if ( $obj->{use_digest} ) {
		$obj->dprint("getting messages as digest $ts\n"); 
		push @args, "digest=1"; 
	}

	
	$obj->dprint("url: ".$urlpath."?".join("&", @args)."\n"); 
	my $res=$obj->lwp->get($urlpath."?".join("&", @args)); 

	if ( ! $res->is_success ) { die "http get to $urlpath failed\n"; }

	my $newts=$res->filename; 
	$obj->dprint("downloaded new ts: ".$newts."\n"); 

	if ( $newts !~ /^\d+$/ ) {  die "uups $newts should be numeric\n"; } 
	
	if ( $obj->{use_digest} ) { 
		$obj->dprint("because we get messages as digest we expect a tar archive here\n"); 
		$obj->{message_count}=$obj->process_tar($res->decoded_content); 
	} else {
		$obj->dprint("we expect a message list as data here\n"); 
		#$obj->dprint($res->decoded_content); 
		$obj->{message_count}=$obj->process_dir($res->decoded_content, $urlpath, $ts); 
	}
	
	if ( ( $newts ) and ( $obj->{use_ts} ))  { 
		open(WRITE, "> $tsfile") or die "Cant open $tsfile to write back timestamp\n"; 
		print WRITE $newts or die "Cant write into $tsfile\n"; 
		close WRITE or die "Cant close $tsfile \n"; 
	}

	# try to wakeup the processor if we got any files 
	if ( $obj->{message_count} > 0 ) {
		my $misc=qtc::misc->new(pidfile=>$obj->{path}."/.qtc_processor.pid");
		$misc->wakeup_processor;
	}
	return $obj->{message_count};
}

#-------------------------------------------------------
=pod

=head2 message_count()

Returns the count of messages of the last syncronization run. 

=cut
#-------------------------------------------------------
sub message_count {
	my $obj=shift; return $obj->{message_count}; 
}

#-------------------------------------------------------
=pod

=head2 process_dir_upload($local_path, $dirdata, $urlpath, $ts)

This is an internal method that compares the remote directory information 
with the local directory.

dirdata is a list of filenames separated by \n

=cut
#-------------------------------------------------------
sub process_dir_upload { 
	my $obj=shift; 
	my $local_path=shift;
	my $dirdata=shift; 
	my $urlpath=shift; 
	my $ts=shift; 
	my %remote;
	foreach my $file (split("\n", $dirdata)) { $remote{$file}=1; }; 

	$obj->dprint("finding out which file needs to be uloaded\n"); 
	
	my @up; 
	foreach my $file (qtc::misc->new()->scan_dir($obj->{path}.$local_path, '.*\.qtc')) { 
		if ( ! $remote{$file} ) {
			#$obj->dprint("$file is not on the remote side\n"); 
			my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
         	         $atime,$mtime,$ctime,$blksize,$blocks)
            	          = stat($obj->{path}.$local_path."/".$file);
			if ( $mtime >= $ts ) { 
				$obj->dprint("file is not to old $mtime >= $ts \n"); 
				$obj->dprint("add ".sprintf("%011d", $mtime)."/".$file."\n"); 
				push @up, sprintf("%011d", $mtime)."/".$file; 
			} else {
				#$obj->dprint("skipping file it is to old $mtime < $ts \n"); 
			}
		}
	}
	@up=map {    
		qtc::msg->new(
			path=>$obj->{path}.$local_path, 
			filename=>basename($_),
		);	
	} sort(@up); 
	if ( ! $obj->{use_digest} ) {
		$obj->dprint("calling publish for ".($#up+1)." files \n"); 
		$obj->publish(@up); 
	} else {
		$obj->dprint("calling publish tar for ".($#up+1)." files \n"); 
		$obj->publish_tar(@up); 
	}
}

#-------------------------------------------------------
=pod

=head2 process_dir($dirdata, $urlpath, $ts)

This is an internal method that compares the local /in directory 
information with a remote directory. 

dirdata is a list of filenames separated by \n

=cut
#-------------------------------------------------------
sub process_dir { 
	my $obj=shift; 
	my $dirdata=shift; 
	my $urlpath=shift; 
	my $ts=shift; 
	if ( ! $dirdata ) { return; }
	my @dir=split("\n", $dirdata); 
	my $die_later=""; 

	$obj->dprint("parsing mesage list\n"); 

	my @dig; 
	foreach my $file (@dir) { 
		if ( ! -e $obj->{path}."/in/".$file ) { 
			$obj->dprint("$file is not known lokally "); 
			if ( $obj->{use_digest_lst} ) {
				$obj->dprint("put it into digest for later fetch\n"); 
				push @dig, $file; 
			} else {
				$obj->dprint("try to download ".$urlpath."/".$file."\n"); 
				my $res=$obj->lwp->get($urlpath."/".$file); 
				if ( ! $res->is_success ) { $die_later.="get $file failed\n"; next; }
				my $path=$obj->{path}."/in";
				$die_later.=$obj->write_content($path, $file, $res->decoded_content); 
			} 
		}
	}
	if ( ! $obj->{use_digest_lst} ) {
		if ( $die_later ) { die $die_later; }
		$obj->dprint("we are done with that directory\n"); 
		return $obj->{message_count}; 
	}

	if ( $#dig < 0 ) { 
		$obj->dprint("We have not found any new message on the server returning\n"); 
		return $obj->{message_count}; 
	}
	
	$obj->dprint("We are downloading a digest.lst from the server now \n"); 
	$obj->dprint(join("\n", @dig)."\n"); 
	my $res=$obj->lwp->post($urlpath, 
		Content_Type => 'form-data',
		Content => [ 
			ts=>$ts,
			digest => [undef, "digest.lst", 'Content-Type'=>"text/plain", Content=>join("\n", @dig) ] 
		],
	);
	if ( ! $res->is_success ) { die "http get dir to $urlpath failed\n"; }
	return $obj->process_tar($res->decoded_content); 
}


#-------------------------------------------------------
=pod

=head2 process_tar($tardata)

This help method unpacks a tar archive, and forwards each file to 
write_content()

=cut
#-------------------------------------------------------
sub process_tar { 
	my $obj=shift; 
	my $tardata=shift; 
	if ( ! $tardata ) { die "We got no Tar data back so we can stop now\n"; }
	else { $obj->dprint("got tar data and it is not empty \n"); }
	my $tarfh=IO::Scalar->new(\$tardata); 
	my $die_later=""; 
	
	my $tar=Archive::Tar->new($tarfh); 
	foreach my $file ($tar->get_files) { 
		my $path=$obj->{path}."/in";
		$obj->dprint("Writing content ".$file->name."\n"); 
		$die_later.=$obj->write_content($path, $file->name, $file->get_content); 
	}	
	if ( $die_later ) { die $die_later; }
	return $obj->{message_count}; 
}

#-------------------------------------------------------
=pod

=head2 write_content($path. $filename, $content)

This helping method savely writes $content to $path/$filename.
If Successful, it increments message_count.

=cut
#-------------------------------------------------------
sub write_content {
	my $obj=shift; 
	my $path=shift; 
	my $file=shift; 
	my $content=shift; 
	my $pathfile=$path."/".$file; 
	my $tmpfile=$path."/.".$$."_".time."_".$file.".tmp"; 
	if ( -e $pathfile ) { return; } # no action if $pathfile is there 
	if ( -e $tmpfile ) { return "write_content: Uuuuups $tmpfile exits\n"; }
	open(WRITE, "> ".$tmpfile) or return "write_content: Cant open file ".$tmpfile."\n"; 
	print  WRITE $content  or return "write_content: Cant write content of ".$pathfile."\n"; 
	close WRITE or return "write_content: cant close file $pathfile\n"; 
	link($tmpfile, $pathfile) or return "write_content: Link to $pathfile failed\n"; 
	unlink($tmpfile) or return "write_content: unlink at $pathfile failed\n"; 
	$obj->{message_count}=$obj->{message_count} + 1; 

	return; 
}


1;
=pod

=head1 AUTHOR

Hans Freitag <oe1src@oevsv.at>

=head1 LICENCE

GPL v3

=cut
