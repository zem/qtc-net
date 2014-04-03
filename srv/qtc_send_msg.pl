#!/usr/bin/perl

use qtc::signature; 
use qtc::msg; 
use Term::ReadLine;

my $misc=qtc::misc->new(); 
my @keyfiles=$misc->scan_dir($ENV{HOME}."/.qtc_private", '((rsa)|(dsa))_.+.key');
my $signature=qtc::signature->new(
	privkey_file=>$ENV{HOME}."/.qtc_private/".$keyfiles[0],
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

