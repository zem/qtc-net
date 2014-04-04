#!/usr/bin/perl

use qtc::signature; 
use qtc::msg; 
use qtc::misc; 
use Term::ReadLine;
my $misc=qtc::misc->new(); 

my @keyfiles=$misc->scan_dir($ENV{HOME}."/.qtc_private", '((rsa)|(dsa))_.+.key');
my $signature=qtc::signature->new(
	privkey_file=>$ENV{HOME}."/.qtc_private/".$keyfiles[0],
);

my $term = Term::ReadLine->new('Input New QTC-Net Message');

my $to = $term->readline("to call: "); 
my $number = $term->readline("number: ");

# ok lets find the message to approve.....
my @msgs;
foreach my $file ($misc->scan_dir($ENV{HOME}."/.qtc/call/$to/telegrams/new", '.+\.qtc')){
	push @msgs, qtc::msg->new(path=>$ENV{HOME}."/.qtc/call/$to/telegrams/new", filename=>$file); 
}

my $qtc; 
foreach my $msg (@msgs) { 
	if ($number == $msg->hr_refnum) {
		$qtc=$msg; 
	}	
}


my $qsp=qtc::msg->new(
	type=>"qsp",
	call=>"oe1src",
	qsl_date=>time,
	to=>$to,
	telegram_checksum=>$qtc->checksum, 
);
$signature->sign($qsp); 

$qsp->to_filesystem($ENV{HOME}."/.qtc/in"); 

