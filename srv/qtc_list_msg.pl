#!/usr/bin/perl

use qtc::misc; 
use qtc::msg; 
use POSIX qw(strftime); 

my $misc=qtc::misc->new(); 

my $call="oe1gis"; 

my @msgs;
foreach my $file ($misc->scan_dir($ENV{HOME}."/.qtc/call/$call/newmsg", '.+\.xml')){
	push @msgs, qtc::msg->new(path=>$ENV{HOME}."/.qtc/call/$call/newmsg", filename=>$file); 
}

print "Number of telegrams: ".($#msgs+1)."\n"; 
print "Telegram numbers: "; 
foreach my $msg (@msgs) { print $msg->hr_refnum." "; }
print "\n\n";


foreach my $msg (@msgs) { 
	print "Number: ".$msg->hr_refnum."\n"; 
	print "Date:\t".strftime("%Y-%m-%d %H:%M:%S UTC", gmtime($msg->msg_date))."\n"; 
	print "from:\t".$msg->from."\n"; 
	print "to:\t".$msg->to."\n"; 
	print "text:\t".$msg->msg."\n"; 
	print "\n"; 
}



