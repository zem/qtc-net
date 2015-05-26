#!/usr/bin/perl 

use qtc::aprs::is;
use qtc::misc; 
use IO::Handle;

my $path=$ENV{QTC_ROOT}; 
if ( ! $path ) { $path=$ENV{HOME}."/.qtc"; }
my $user; # nocall
my $pass; # 1337
my $peer="euro.aprs2.net:14580";
my $filter="r/48.2090/16.3700/500 t/sm";
my $debug=0; 
my $daemon=1; 
my $pidfile=""; 

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
	if ($_ eq  "--pidfile") {
		$pidfile=shift(@ARGV); 
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
	# deamon mode is coming, sure 
	if ($_ eq  "--debug") {
		$debug=1;
		next; 
	}
}


if ( ! $pidfile ) { $pidfile=$path."/.aprsgate.pid"; }
my $misc=qtc::misc(pidfile=>$pidfile); 

# do some setup stuff 
if ( $daemon ) {
	my $pid=fork(); 
	if ( $pid != 0 ) { exit; }

	if ( ! -e $pid ) {
		open(PID, "> ".$pid) or die "Cant open pidfile\n"; 
		print(PID $$) or die "can't write to pid file\n"; 
		close PID; 
		if ( $misc->get_pid() != $$ ) { die "the pid in the file we wrote just now is not ours\n"; }
		
		$SIG{TERM}=sub { unlink($pidfile); exit; }; # link pidfile destruction to TERM and KILL
		$SIG{KILL}=sub { unlink($pidfile); exit; }; # link pidfile destruction to TERM and KILL
	} else { die "There is a pid file and it is not ours\n"; }
}

if ( $log ) { 
	close STDERR; 
	open(STDERR, ">> ".$log) or die "can't open logfile ".$log." \n";	
	STDERR->autoflush(1); 
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
	debug=>$debug,
); 

$is->eventloop; 
}; 
if ( $@ ) { print STDERR $@; } 
sleep 10; 
print STDERR "-----------------------------------------------------------------------\n";
print STDERR "reconnecting\n";
print STDERR "-----------------------------------------------------------------------\n";
}

