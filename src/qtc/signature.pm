#Signature abstraction module for qtc net. 
package qtc::signature; 
use Data::Dumper;
use File::Basename;
use qtc::msg; 

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::DSA;
use MIME::Base64;
use Digest::SHA qw(sha256_hex); 
#use Crypt::Rijndael;

#######################################################
# obviously generic right now
########################################################
sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	
	# expect an pubkey hash {} that contains key validated qtc::msg objects for 
	#       signature verification, ordered by their key ID
	# expect a privkey string for object signing 
	# expect a privkey_type = rsa|dsa
	# and a key_id for signing of data 
	# or a privkey_file 
	# 
	# in case of a newly generated key this can be done by 
	#     privpath (that one should exist) 
	#     call
	#     rsa_keygen ( =1 or later dsa keygen ) 
	#
	if ( $obj->{rsa_keygen} ) {
		$obj->rsa_keygen; 
	}

	#if ( $obj->{password} ) {
	#	my $salt="it is stupid to store the aes keyhash into a directory name in the first place"; 
	#	$obj->{aes}=Crypt::Rijndael->new(pack("H*", sha256_hex($salt.$obj->{password})), Crypt::Rijndael::MODE_CBC()); 
	#}
	if ( $obj->{privkey_file} ) {
		open(IN, "< $obj->{privkey_file}") or die "can't read privkey\n"; 
		$obj->{privkey}=""; 
		while (<IN>) { $obj->{privkey}.=$_; }
		close IN; 
		#if ( $obj->{aes} ) { 
		#	$obj->{privkey}=$obj->{aes}->decrypt($obj->{privkey}); 
		#}
		my $basename=basename($obj->{privkey_file}); 
		$basename=~s/\.key$//g; 
		my ($ttyp, $tcall, $tkey_id) = split(/_/, $basename); 
		if ( ( ! $obj->{privkey_type}) and ( $ttyp) ) {$obj->{privkey_type}=$ttyp; }
		if ( ( ! $obj->{key_id}) and ( $tkey_id) ) {$obj->{key_id}=$tkey_id; }
	}

	return $obj; 
}

sub rsa_keygen {
	my $o=shift; 

	my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
	$rsa->use_sha256_hash; 
	my $keystring=$rsa->get_public_key_string;
	chomp($keystring); 
	$keystring=~s/^(-----BEGIN RSA PUBLIC KEY-----)|(-----END RSA PUBLIC KEY-----)$//g;

	my $keydata=decode_base64($keystring) or die "Cant decode keystring\n"; 
	my $key_id=sha256_hex($keydata);

	my $pubkey=qtc::msg->new(
		type=>"pubkey",
		call=>$o->{call},
		key_date=>time,
		key_type=>"rsa",
		key_id=>$key_id,
		key=>unpack("H*", $keydata),
	); 

	$pubkey->signature(unpack("H*", $rsa->sign($pubkey->signed_content_bin)), $key_id); 

	my $path=$o->{privpath};

	my @dir=$pubkey->scan_dir($path, 'rsa_'.$call.'.*'); 
	if ( $#dir >= 0 ) { die "there is already a key, it may be a bad idea to write a new one\n"; }
	
	if ( $o->{debug} ) { print STDERR "Writing Keys to $path\n"; }
	
	$pubkey->ensure_path($path); 
	$pubkey->to_filesystem($path); 
	
	$o->{privkey_file}="$path/rsa_".$o->{call}."_".$key_id.".key";

	open(WRITE, "> ".$o->{privkey_file}) or die "Can't write key to filesystem\n";
	#if ( $obj->{aes} ) {
	#	my $x=$rsa->get_private_key_string;
	#	my $l=length($x);
	#	
	#	print WRITE $obj->{aes}->encrypt($rsa->get_private_key_string) or die "Can't write key to filesystem (write)\n"; 
	#} else {
		print WRITE $rsa->get_private_key_string or die "Can't write key to filesystem (write)\n"; 
	#}
	close WRITE or die "Can't write key to filesystem (close)\n";
	
	# activate this key in the system....
	$pubkey->link_to_path($o->{path}."/in"); 		
}



sub sign {
	my $obj=shift; 
	my $msg=shift;
	
	if ( ! $obj->{privkey} ) { die "I do not know the key to sign with\n"; }
	if ( ! $obj->{key_id} ) { die "I do not know the key_id to sign with\n"; }
	if ( 	$obj->{privkey_type} !~ /^(rsa|dsa)$/ ) { die "privkey_type eq $obj->{privkey_type} use rsa|dsa\n"; }
	if ( $obj->{privkey_type} eq "rsa" ) {
		
		my $rsa=Crypt::OpenSSL::RSA->new_private_key($obj->{privkey}) or die "Can't read use private key\n"; 
		$rsa->use_sha256_hash; 
		$msg->signature(unpack("H*", $rsa->sign($msg->signed_content_bin)), $obj->{key_id}); 

	} elsif ($obj->{privkey_type} eq "dsa") {
		die "This is possible but not yet implemented \n"; 
	}

}

sub verify {
	my $obj=shift; 
	my $signed_content_bin=shift;
	my $signature=shift;
	my $signature_key_id=shift;
	#print STDERR "$signed_content_bin $signature\n"; 
	$signature=pack("H*", $signature); 
	
	if ( ! $obj->{pubkey}->{$signature_key_id} ) { die "I do not have a key to verify with\n"; }

	my $pubkey=$obj->{pubkey}->{$signature_key_id};

	if ( $pubkey->key_type eq "rsa" ) {
		#print STDERR $obj->prepare_rsa_pubkey($pubkey->key);
 		my $rsa=Crypt::OpenSSL::RSA->new_public_key($obj->prepare_rsa_pubkey($pubkey->key)) or die "Cant load public Key\n";
		#print "foo\n"; 
		$rsa->use_sha256_hash; 
		if ($rsa->verify($signed_content_bin, $signature)) {
			#print STDERR "verification succeeded\n"; 
			return 1;
		}
		#print STDERR Dumper($pubkey); 
	} elsif ($pubkey->key_type eq "dsa" ) {
		die "dsa verification not yet implemented\n"; 
	}
	return 0; 
}

sub prepare_rsa_pubkey {
	my $obj=shift; 
	my $key=shift; 
	return "-----BEGIN RSA PUBLIC KEY-----\n".encode_base64(pack("H*", $key))."-----END RSA PUBLIC KEY-----\n"
}

sub prepare_dsa_pubkey {
	my $obj=shift; 
	my $key=shift; 
	return "-----BEGIN DSA PUBLIC KEY-----\n".encode_base64(pack("H*", $key))."-----END DSA PUBLIC KEY-----\n"
}

1; 
