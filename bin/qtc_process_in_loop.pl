#!/usr/bin/perl
use qtc::processor;

my $path=$ENV{QTC_ROOT}; 
my $log=$ENV{QTC_PROCESSOR_LOG}; 
my $daemon=1; 
my $archive=0; 

while ($_=shift(@ARGV)) {
	if ($_ eq  "-d") {
		$path=shift(@ARGV); 
		next; 
	}
	if ($_ eq  "-l") {
		$log=shift(@ARGV); 
		next; 
	}
	if ($_ eq  "--archive") {
		$archive=1;
		next; 
	}
	if ($_ eq  "--nodaemon") {
		$daemon=0;
		next; 
	}
}

my $processor=qtc::processor->new(
	root=>$path,
	log=>$log, 
	daemon=>$daemon, 
	archive=>$archive, 
); 
$processor->process_in_loop; 

