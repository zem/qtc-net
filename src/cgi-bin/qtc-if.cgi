#!/usr/bin/perl

use qtc::misc; 
use qtc::msg; 
use CGI::Simple; 
use CGI::Simple::Standard; 
use Archive::Tar; 

my $root="/home/zem/.qtc"; 


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
	my $msg; 
	eval { 
		$putdata=unpack("H*", $putdata); 
		$msg=qtc::msg->new(hex=>$putdata);
		$msg->to_filesystem("/tmp"); 
	}; 
	if ( $@ ) { 
		print $q->header(
			-type=>'text/plain',
			-status=>400
		);
		print $@; 
	} else { 
		print $q->header(
			-type=>'text/plain',
			-status=>200
		);
		print $msg->filename; 
		print Dumper(\%ENV); 
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
	open(READ, "< ".$root.$path) or die "cant open $root$path\n"; 
	while(<READ>) { print; }
	close READ; 
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
			-status=>200,
		);
		print $newts."\n";
		print join("\n", @ret);
	} else { 
		# getting a digest as multipart
		print $q->header(
			#-type=>'application/octet-stream',
			-type=>'application/x-tar',
			-attachment => $newts,
			-status=>200,
		);
		my $tar=Archive::Tar->new; 
		foreach my $file (@ret) {
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

