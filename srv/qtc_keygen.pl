#!/usr/bin/perl

use qtc::signature; 
use qtc::msg; 
use Crypt::OpenSSL::RSA;
use Digest::SHA qw(sha256_hex);
use MIME::Base64;

my $call="oe1src"; 

my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
$rsa->use_sha256_hash; 
my $keystring=$rsa->get_public_key_string;
chomp($keystring); 
my $key_id=sha256_hex($pubkey);

my $pubkey=qtc::msg->new(
	type=>"pubkey",
	call=>$call,
	key_type=>"rsa",
	key_id=>$key_id,
	key=>$keystring,
); 

# selfsign message first
$pubkey->signature(encode_base64($rsa->sign($pubkey->checksum)), $key_id); 

my $path=$ENV{HOME}."/.qtc_private";

$pubkey->ensure_path($path); 
$pubkey->to_filesystem($path); 

open(WRITE, "> $path/rsa_$call.key");
print WRITE $rsa->get_private_key_string; 
close WRITE;


