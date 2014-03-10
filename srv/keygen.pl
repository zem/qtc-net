#!/usr/bin/perl

use qtc::signature; 
use qtc::msg; 
use Crypt::OpenSSL::RSA;
use MIME::Base64;

my $call="oe1src"; 

my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
$rsa->use_sha256_hash; 

my $pubkey=qtc::msg->new(
	type=>"pubkey",
	call=>$call,
	key_type=>"rsa", 
	key=>$rsa->get_public_key_string,
); 

# selfsign message first
$pubkey->signature(encode_base64($rsa->sign($pubkey->checksum))); 

$pubkey->to_filesystem("."); 

open(WRITE, "> rsa_$call.key");
print WRITE $rsa->get_private_key_string; 
close WRITE; 

