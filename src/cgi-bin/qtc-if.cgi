#!/usr/bin/perl

use qtc::misc; 
use qtc::msg; 
use CGI::Simple; 
use CGI::Simple::Standard; 

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
	print $q->header(
		-type=>'application/octet-stream',
		-status=>200,
	);
	print $newts."\n";
	print join("\n", @ret); 
	exit; 
}

print $q->header(
	-type=>'application/octet-stream',
	-status=>400,
);
print "Cant understand request\n";
print $q->Dump; 
print $q->PrintEnv; 

