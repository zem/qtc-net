#!/usr/bin/perl
use Data::Dumper; 
use qtc::msg; 

my $msg=qtc::msg->new(path=>$ARGV[0], filename=>$ARGV[1]); 

$msg->has_valid_type; 
$msg->is_object_valid; 

print "Hello\n";

print Dumper($msg); 
