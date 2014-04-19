#!/usr/bin/perl

use qtc::signature; 
use qtc::msg; 

my $call=lc($ARGV[0]);

if (( ! $call ) or ( $call !~ /^([a-z]|[0-9]|\/)+$/ )) {
	print "You have to set a call at first command line argument for the key generator.\n";
	print "I am exiting now, either because call $call is empty or it does not match the allowed characters for a call.\n"; 
	exit 1; 
} 

my $path=$ENV{HOME}."/.qtc_private";

my $sig=qtc::signature->new(
	path=>$ENC{HOME}."/.qtc"; 
	privpath=>$path, 
	call=>$call, 
	rsa_keygen=>1,
	debug=>1,
); 

