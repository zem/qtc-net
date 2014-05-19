#!/usr/bin/perl 

use qtc::aprs::is;

my $path=$ENV{QTC_ROOT}; 
if ( ! $path ) { $path=$ENV{HOME}."/.qtc"; }
my $user; # nocall
my $pass; # 1337
my $peer="euro.aprs2.net:14580";
my $filter="r/48.2090/16.3700/1000 t/m";

while ($_=shift(@ARGV)) {
	if ($_ eq  "-u") {
		$user=shift(@ARGV); 
		next; 
	}
	if ($_ eq  "-p") {
		$pass=shift(@ARGV); 
		next; 
	}
	if ($_ eq  "--hostport") {
		$peer=shift(@ARGV); 
		next; 
	}
	if ($_ eq  "--filter") {
		$filter=shift(@ARGV); 
		next; 
	}
	if ($_ eq  "-pd") {
		$privpath=shift(@ARGV); 
		next; 
	}
	if ($_ eq  "-d") {
		$path=shift(@ARGV); 
		next; 
	}
	if ($_ eq  "-l") {
		$log=shift(@ARGV); 
		next; 
	}
	# deamon mode is coming, sure 
	if ($_ eq  "--nodaemon") {
		$daemon=0;
		next; 
	}
}

while(1){
eval {
my $is=qtc::aprs::is->new(
	PeerAddr=>$peer,
	user=>$user,
	pass=>$pass,
	filter=>$filter,
	path=>$path,
	privpath=>$privpath,
); 

$is->eventloop; 
}; 
if ( $@ ) { print STDERR $@; } 
sleep 10; 
print STDERR "-----------------------------------------------------------------------\n";
print STDERR "reconnecting\n";
print STDERR "-----------------------------------------------------------------------\n";
}
