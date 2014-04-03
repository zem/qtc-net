#!/usr/bin/perl

use qtc::signature; 
use qtc::msg; 
use Term::ReadLine;

my $signature=qtc::signature->new(
	privkey_file=>$ENV{HOME}."/.qtc_private/rsa_oe1src_ed9eaed81acd5bc15ab47eaf2ee920956295fb900ad750befa14d9fc0af925cb.key",
);


my $term = Term::ReadLine->new('Input New QTC-Net Message');

my $from = $term->readline("from call: "); 
my $to = $term->readline("to call: "); 
my $msg = $term->readline("message: ");

my $msg=qtc::msg->new(
	type=>"telegram",
	call=>"oe1src",
	telegram_date=>time,
	from=>$from, 
	to=>$to,
	telegram=>$msg,
);
$signature->sign($msg); 

$msg->to_filesystem($ENV{HOME}."/.qtc/in"); 

