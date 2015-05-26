#!/usr/bin/perl 

use IO::Handle;
use qtc::interface::http; 
use qtc::misc; 

my $daemon=0;

if ( $#ARGV == -1 ) { print "Usage: $0 [-d PATH_TO_QTC] [--daemon] [-l LOG_FILE] [-p PIDFILE] [-t sleeptime] url [url2] ...\n"; exit; }

my $path=$ENV{HOME}."/.qtc"; 
my $log;
my $pidfile;
my $timer=0; 

while ($ARGV[0] ~ /^-/ ) {
	if ( $ARGV[0] eq "-d" ) {
		shift(@ARGV); 
		$path=shift(@ARGV); 
	}
	if ( $ARGV[0] eq "--daemon" ) {
		shift(@ARGV); 
		$daemon=1;
		if ( ! $timer ) { $timer=300; }	
	}
	if ( $ARGV[0] eq "-p" ) {
		shift(@ARGV); 
		$pidfile=shift(@ARGV); 
	}
	if ( $ARGV[0] eq "-l" ) {
		shift(@ARGV); 
		$log=shift(@ARGV); 
	}
	if ( $ARGV[0] eq "-t" ) {
		shift(@ARGV); 
		$timer=shift(@ARGV); 
	}
}

if ( ! $pidfile ) { $pidfile=$path."/.qtc_sync_http.pid"; } 

my $misc=qtc::misc->new(pidfile=>$pidfile); 
if ( $daemon ) { $misc->daemonize(); }
if ( $log ) {
	close STDERR; 
	open(STDERR, ">> ".$log) or die "can't open logfile ".$log." \n";	
	STDERR->autoflush(1); 
}


while (1) {
	# url may be http://localhost/qtc_if.cgi
	foreach my $url (@ARGV) {
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
	}
	if ( $timer ) { sleep($timer); } else { exit; }
}
