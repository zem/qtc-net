# this is the http part of the interface
package qtc::interface::http;
use Digest::SHA qw(sha256_hex); 
use LWP::UserAgent; 
use IO::Scalar; 
use Archive::Tar; 
use qtc::msg;
use qtc::misc;
use qtc::interface;
@ISA=("qtc::interface"); 

sub new { 
	my $obj=shift; 
	my %arg=(@_); 
	$obj=$obj->SUPER::new(%arg);

	$obj->{can_publish}=1; 
	$obj->{can_sync}=1; 
	
	# features
	if ( ! $obj->{use_ts} ) { $obj->{use_ts}=1; } 
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

sub url { my $obj=shift; return $obj->{url}; }
sub lwp { my $obj=shift; return $obj->{lwp}; }


sub publish {
	my $obj=shift; 
	my $msg=shift; 

	if ( ! $msg ) { die "I need a qtc::msg object here\n"; }

	my $res=$obj->lwp->put($url, 
		"Content-Type"=>"application/octet-stream",
		Content=>pack("H*", $msg->as_hex),
	); 

	if ( ! $res->is_success ) { die "File Upload not succeeded\n"; }
}

sub sync {
	my $obj=shift; 
	my $path=shift; 
	
	my $urlpath=$obj->url.$path; 
	my $tsfile;
	$obj->{message_count}=0; 

	my @args;

	if ( $obj->{use_ts} ) {
		my $ts=0; 
		$tsfile=$obj->{ts_dir}."/".sha256_hex($urlpath); 
		
		if ( -e $tsfile ) {
			open(READ, "< $tsfile") or die "I cant open $tsfile for reading \n"; 
			while(<READ>){ $ts=$_; }
			close READ; 
		}
		push @args, "ts=$ts"; 
	}

	if ( $obj->{use_digest} ) {
		push @args, "digest=1"; 
	}

	my $res=$obj->lwp->get($urlpath."?".join("&", @args)); 

	if ( ! $res->is_success ) { die "http get to $urlpath failed\n"; }

	my $newts=$res->filename; 

	if ( $newts !~ /^\d+$/ ) {  die "uups $newts should be numeric\n"; } 
	
	if ( $obj->{use_digest} ) { 
		$obj->{message_count}=$obj->process_tar($res->decoded_content); 
	} else {
		$obj->{message_count}=$obj->process_dir($res->decoded_content, $urlpath, $ts); 
	}
	
	if ( ( $newts ) and ( $obj->{use_ts} ))  { 
		open(WRITE, "> $tsfile") or die "Cant open $tsfile to write back timestamp\n"; 
		print WRITE $newts or die "Cant write into $tsfile\n"; 
		close WRITE or die "Cant close $tsfile \n"; 
	}
	return $obj->{message_count};
}

sub message_count {
	my $obj=shift; return $obj->{message_count}; 
}

sub process_dir { 
	my $obj=shift; 
	my $dirdata=shift; 
	my $urlpath=shift; 
	my $ts=shift; 
	if ( ! $dirdata ) { return; }
	my @dir=split("\n", $dirdata); 
	my $die_later=""; 

	my @dig; 
	foreach my $file (@dir) { 
		if ( ! -e $obj->{path}."/in/".$file ) { 
			if ( $obj->{use_digest_lst} ) {
				push @dig, $file; 
			} else {
				my $res=$obj->lwp->get($urlpath."/".$file); 
				if ( ! $res->is_success ) { $die_later.="get $file failed\n"; next; }
				my $pathfile=$obj->{path}."/in/".$file;
				$die_later.=$obj->write_content($pathfile, $res->decoded_content); 
			} 
		}
	}
	if ( ! $obj->{use_digest_lst} ) {
		if ( $die_later ) { die $die_later; }
		return $obj->{message_count}; 
	}

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


sub process_tar { 
	my $obj=shift; 
	my $tardata=shift; 
	my $tarfh=IO::Scalar->new(\$tardata); 
	my $die_later=""; 
	
	my $tar=Archive::Tar->new($tarfh); 
	foreach my $file ($tar->get_files) { 
		my $pathfile=$obj->{path}."/in/".$file->name;
		$die_later.=$obj->write_content($pathfile, $file->get_content); 
	}	
	if ( $die_later ) { die $die_later; }
	return $obj->{message_count}; 
}

sub write_content {
	my $obj=shift; 
	my $pathfile=shift; 
	my $content=shift; 
	my $tmpfile=$$."_".time."_".$pathfile.".tmp"; 
	if ( -e $pathfile ) { return; } # no action if $pathfile is there 
	if ( -e $tmpfile ) { return "write_content: Uuuuups $tmpfile exits\n"; }
	open(WRITE, "> ".$tmpfile) or return "write_content: Cant open file ".$pathfile."\n"; 
	print  WRITE $content  or return "write_content: Cant write content of ".$pathfile."\n"; 
	close WRITE or return "write_content: cant close file $pathfile\n"; 
	link($tmpfile, $pathfile) or return "write_content: Link to $pathfile failed\n"; 
	unlink($tmpfile) or return "write_content: unlink at $pathfile failed\n"; 
	$obj->{message_count}=$obj->{message_count} + 1; 

	return; 
}


1;