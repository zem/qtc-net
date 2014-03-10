#Signature abstraction module for qtc net. 
package qtc::signature; 

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::DSA;
use MIME::Base64;

#######################################################
# obviously generic right now
########################################################
sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	
	# expect an pubkey array [] that contains key qtc::msg objects for signature verification
	# expect a privkey string for object signing 
	# expect a privkey_type = rsa|dsa

	return $obj; 
}

sub sign {
	my $obj=shift; 
	my $checksum=shift;
	
	if ( ! $obj->{privkey} ) { die "I do not know the key to sign with\n"; }
	if ( 	$obj->{privkey_type} !~ /^(rsa|dsa)$/ ) { die "privkey_type eq $obj->{privkey_type} use rsa|dsa\n"; }
	if ( $obj->{privkey_type} eq "rsa" ) {
		
		my $rsa=Crypt::OpenSSL::RSA->new_private_key($obj->{privkey}) or die "Can't read use private key\n"; 
		$rsa->use_sha256_hash; 
		return encode_base64($rsa->sign($checksum)); 

	} elsif ($obj->{privkey_type} eq "dsa") {
		die "This is possible but not yet implemented \n"; 
	}

}

sub verify {
	my $obj=shift; 
	my $checksum=shift;
	my $signature=shift;
	$signature=decode_base64($signature); 
	
	if ( $#{$obj->{pubkey}} < 0 ) { die "I do not know the key to sign with\n"; }

	foreach my $pubkey (@{$obj->{pubkey}}){
		if ( $pubkey->key_type eq "rsa" ) {
 			my $rsa->new_public_key($pubkey->key) or die "Cant load public Key\n";
			$rsa->use_sha256_hash; 
			if ($rsa->verify($checksum, $signature)) {
				return 1; 
			}
		} elsif ($pubkey->key_type eq "dsa" ) {
			die "dsa verification not yet implemented\n"; 
		}
	}
	return 0; 
}


1; 
