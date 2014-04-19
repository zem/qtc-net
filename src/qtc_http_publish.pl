#!/usr/bin/perl 

use qtc::interface::http; 
use qtc::msg; 
use File::Basename; 

if ( $#ARGV == -1 ) { print "Usage: $0 url [file1] [file2] ...\n"; exit; }

$url=shift(@ARGV); 
my $if=qtc::interface::http->new(url=>$url); 

foreach my $file (@ARGV) {
	my $msg=qtc::msg->new(path=>dirname($file), filename=>basename($file)); 
	$if->publish($msg); 
}

