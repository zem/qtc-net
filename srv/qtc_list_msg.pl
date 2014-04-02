#!/usr/bin/perl

use qtc::misc; 
use qtc::msg; 
use POSIX qw(strftime); 

my $misc=qtc::misc->new(); 

my $call="oe1gis"; 

my @msgs;
foreach my $file ($misc->scan_dir($ENV{HOME}."/.qtc/call/$call/telegrams/new", '.+\.qtc')){
	push @msgs, qtc::msg->new(path=>$ENV{HOME}."/.qtc/call/$call/telegrams/new", filename=>$file); 
}

print "Number of telegrams: ".($#msgs+1)."\n"; 
print "Telegram numbers: "; 
foreach my $msg (@msgs) { print $msg->hr_refnum." "; }
print "\n\n";


foreach my $msg (@msgs) { 
	print "Number: ".$msg->hr_refnum."\n"; 
	print "Date:\t".strftime("%Y-%m-%d %H:%M:%S UTC", gmtime($msg->telegram_date))."\n"; 
	print "from:\t".$msg->from."\n"; 
	print "to:\t".$msg->to."\n"; 
	print "text:\t".$msg->telegram."\n"; 
	print "\n"; 
}



