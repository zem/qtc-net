#!/usr/bin/perl
use qtc::misc; 
use qtc::msg; 
use CGI::Simple; 
$CGI::Simple::DISABLE_UPLOADS = 0;
use CGI::Simple::Standard;
use IO::Scalar; 
use Archive::Tar; 
use File::Basename; 

my $root=$ENV{QTC_ROOT}; 
if ( ! $root ) { $root=$ENV{HOME}."/.qtc" }


sub publish_posted_msg {
	my $data=shift;
	my $filename; 
	eval { 
		my $msg; 
		$data=unpack("H*", $data); 
		$msg=qtc::msg->new(hex=>$data);
		$msg->to_filesystem($root."/in"); 
		$msg->{pidfile}=$root."/.qtc_processor.pid"; 
		$msg->wakeup_processor;
		$filename=$msg->filename; 
	};
	return $@, $filename; 
}


my $putdata;
if ( $ENV{REQUEST_METHOD} eq 'PUT' ) {
	while(<STDIN>){ 
		$putdata.=$_; 
	}
}

my $q = CGI::Simple->new;
if (( ! $putdata ) and $q->param("POSTDATA") ) {
		print $q->header(
			-type=>'text/plain',
			-status=>500
		);
		print "This would work but there is some bug when reading binary data either in CGI::Simple or even Perl\n"; 
	#$putdata=$q->param("POSTDATA"); 
}
if ( $putdata ) {
	my $err;
	my @processed; 
	my %mtype=(
		"application/tar"=>1,
		"application/x-tar"=>1,
		"application/x-gtar"=>1,
		"multipart/x-tar"=>1, 
		"application/x-compress"=>1, 
		"application/x-compressed"=>1,
	); 
	if ( $mtype{$ENV{CONTENT_TYPE}} ) {  # if we have got a tar archive
		my $tarfh=IO::Scalar->new(\$putdata);
		my $tar=Archive::Tar->new($tarfh);
		foreach my $file ($tar->get_files) {
			my ($ret, $filename)=publish_posted_msg($file->get_content);
			if ( $ret ) { 
				$err.="For File: $filename the followin error occured:\n"; 
				$err.=$ret; 
				$err.="-----------------------------------------\n";
			} else {
				push @processed, $file->name;
			}
		}	
	} else {
			my ($ret, $file)=publish_posted_msg($putdata);
			if ( $ret ) { 
				$err.=$ret; 
			} else {
				push @processed, $file;
			}
	}
	if ( $err ) { 
		print $q->header(
			-type=>'text/plain',
			-status=>400
		);
		print $err;
		print "----------------------------------------------\n";
		print "well processed files:\n"; 
		print join("\n", @processed); 
	} else { 
		print $q->header(
			-type=>'text/plain',
			-status=>200
		);
		print join("\n", @processed); 
		#print Dumper(\%ENV); 
	}
	exit; 
} 

my $path=$q->path_info();
# I do not trust the underlying libs as well as apache to prevent this
# A test shows that in my apache2 CGI there was no path info below the CGI
# but it is safer to check again here
if ( $path =~ /\.\./ ) {
	print $q->header(
		-type=>'text/plain',
		-status=>400,
	);
	print "your path $path contains .. thats forbidden\n";
	exit;
}

# return file 
if ( -f $root.$path ) { 
	print $q->header(
		-type=>'application/octet-stream',
		-status=>200,
	);
	eval {
		# opening a message and parse it first means more CPU but is safer at all
		my $msg=qtc::msg->new(path=>dirname($root.$path), filename=>basename($root.$path)); 
		print pack("H*", $msg->as_hex);
	}; print STDERR $@;   
	exit; 
}

# return file 
if ( -d $root.$path ) { 
	my $m=qtc::misc->new; 
	@lst=$m->scan_dir($root.$path, '^[a-z]+_([a-z]|[0-9]|-)+_([a-f]|[0-9])+\.qtc$'); 
	my $newts=time; 
	my @ret;
	my $ts=$q->param("ts"); if ( !$ts) { $ts=0; }
	foreach my $file (@lst) {
		my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
                  $atime,$mtime,$ctime,$blksize,$blocks)
                      = stat($root.$path."/".$file);
		if ( $mtime > $ts ) { 
			push @ret, $file; 
		}
	}
	if ( ! $q->param("digest") ) {
		print $q->header(
			-type=>'text/plain',
			-attachment => $newts,
			-status=>200,
		);
		print join("\n", @ret);
	} else { 
		# getting a digest as multipart
		print $q->header(
			#-type=>'application/octet-stream',
			-type=>'application/x-tar',
			-attachment => $newts,
			-status=>200,
		);
		my $dig=$q->param("digest");
		my %x;
		if ( $dig eq "digest.lst" ){
			my $fh=$q->upload($dig);
			while (<$fh>) { 
				chomp;
				$x{$_}=1;
			}
		}
		my $tar=Archive::Tar->new; 
		foreach my $file (@ret) {
			if (( $dig eq "digest.lst" ) and ( ! $x{$file} )) { next; }
			eval {
				my $msg=qtc::msg->new(path=>$root.$path, filename=>$file); 
				$tar->add_data($msg->filename, pack("H*", $msg->as_hex));
			}; print STDERR $@; 
		}
		print $tar->write;
	}
	exit; 
}

print $q->header(
	-type=>'application/octet-stream',
	-status=>400,
);
print "Cant understand request\n";
print $q->Dump; 
print $q->PrintEnv; 

