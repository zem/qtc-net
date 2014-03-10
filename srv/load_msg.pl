#!/usr/bin/perl 

use qtc::msg; 
use Data::Dumper; 

sub dprint {
	return; 
	print @_; 
}


my $msg=qtc::msg->new(filename=>"msg_oe1src_d9382ee0ab8bd0a36ced5c99be10cbca1bedcf84548a00ac5a710dde7e1db956.xml"); 

print Dumper($msg); 
print "hello\n"; 

print $msg->as_xml; 

