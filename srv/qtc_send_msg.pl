#!/usr/bin/perl

use qtc::signature; 
use qtc::msg; 
use Term::ReadLine;

my $signature=qtc::signature->new(
	privkey_file=>$ENV{HOME}."/.qtc_private/rsa_oe1src_68a1a244b9832ae502aed7176c184dace6814b831a741cc9a721322973b38911.key",
#	privkey_type=>"rsa", 
#	key_id=>"68a1a244b9832ae502aed7176c184dace6814b831a741cc9a721322973b3891", 
);


my $term = Term::ReadLine->new('Input New QTC-Net Message');

my $from = $term->readline("from call: "); 
my $to = $term->readline("to call: "); 
my $msg = $term->readline("message: ");

my $msg=qtc::msg->new(
	type=>"msg",
	call=>"oe1src",
	msg_date=>time,
	from=>$from, 
	to=>$to,
	msg=>$msg,
);
$signature->sign($msg); 

$msg->to_filesystem($ENV{HOME}."/.qtc/in"); 

