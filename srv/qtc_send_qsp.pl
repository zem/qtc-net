#!/usr/bin/perl

use qtc::signature; 
use qtc::msg; 
use qtc::misc; 
use Term::ReadLine;
my $misc=qtc::misc->new(); 

my $signature=qtc::signature->new(
	privkey_file=>$ENV{HOME}."/.qtc_private/rsa_oe1src_68a1a244b9832ae502aed7176c184dace6814b831a741cc9a721322973b38911.key",
#	privkey_type=>"rsa", 
#	key_id=>"68a1a244b9832ae502aed7176c184dace6814b831a741cc9a721322973b3891", 
);


my $term = Term::ReadLine->new('Input New QTC-Net Message');

my $to = $term->readline("to call: "); 
my $number = $term->readline("number: ");

# ok lets find the message to approve.....
my @msgs;
foreach my $file ($misc->scan_dir($ENV{HOME}."/.qtc/call/$to/newmsg", '.+\.qtc')){
	push @msgs, qtc::msg->new(path=>$ENV{HOME}."/.qtc/call/$to/newmsg", filename=>$file); 
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

