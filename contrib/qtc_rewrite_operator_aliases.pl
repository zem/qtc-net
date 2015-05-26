#!/usr/bin/perl
# I used this script in the early times of the net when 
# I made -NUM calls possible to rewrite all of the operator 
# messages
use Data::Dumper; 
use qtc::msg; 
use qtc::publish; 
use File::Basename; 

my $file=shift(@ARGV); 
my $privdir=shift(@ARGV); 

my $verbose=0; 
if ($file eq "-v") {
	$file=shift(@ARGV); 
	$verbose=1;
}

my $msg=qtc::msg->new(path=>dirname($file), filename=>basename($file)); 

$msg->has_valid_type; 
$msg->is_object_valid; 

if ( $verbose ) {
	print "Printing verbose Output of perl Object $file \n\n";
	print Dumper($msg);
} else {
	print "\n--- !".basename($file)."\n";
	print "type: ".$msg->type."\n"; 
	print "version: ".$msg->version."\n"; 
	print "call: ".$msg->call."\n"; 
	print "hr_refnum: ".$msg->hr_refnum."\n"; 
	print "checksum: ".$msg->checksum."\n"; 
	if ( $msg->checksum_period ) {
		print "checksum_period: ".$msg->checksum_period."\n"; 
		print "prev_checksum: ".$msg->prev_checksum."\n"; 
		print "next_checksum: ".$msg->next_checksum."\n"; 
	}
	print "signature: ".$msg->signature."\n"; 
	print "signature_key_id: ".$msg->signature_key_id."\n"; 
	foreach my $field (sort keys %{$qtc::msg::msg_types{$msg->type}}) {
		foreach my $val ($msg->value($field)) {
			print "$field: $val\n"; 
		}
	}
	my $publish=qtc::publish->new(
			path=>"/var/spool/qtc/messages", 
			privpath=>$privdir, 
		);
	my @follow; 
	foreach ($msg->set_of_followings) {
		s/\/\//-/g; 
		push(@follow, $_); 
	}
	my @alias; 
	foreach ($msg->set_of_aliases) {
		s/\/\//-/g; 
		push(@alias, $_); 
	}
	$publish->operator(
		set_of_aliases=>[@alias],
		set_of_followings=>[@follow],
	);
	foreach my $val (@follow) {
		print "follow: $val\n"; 
	}
	foreach my $val (@alias) {
		print "alias: $val\n"; 
	}

	
} 
print "\n";
