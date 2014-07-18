#-----------------------------------------------------------------------------------
=pod

=head1 NAME

qtc::signature - class for signature creation and verification 

=head1 SYNOPSIS

	use qrc::signature;

	my $sig=qtc::signature->new(
		pubkey=>$keyhash,
	);

	if (! $sig->verify($msg->signed_content_bin, $msg->signature, $msg->signature_key_id) ) { 
		die "Signature verification for message ".$msg->checksum." failed\n"; 
	}

or

	use qtc::signature;
	
	$obj->{signature}=qtc::signature->new(
		privkey_file=>$obj->{privkey_file},
		password=>$obj->{password},
		
		path=>$obj->{path}, 
		privpath=>$obj->{privpath}, 
		call=>$obj->{call},
		
		dsa_keygen=>$obj->{dsa_keygen},
		rsa_keygen=>$obj->{rsa_keygen},
	);

	$obj->{signature}->sign($msg); 


=head1 DESCRIPTION

QTC Signature is a signature abstraction library for qtc::msg it helps 
you to create and verify signatures of qtc messages. It will (soon) implement 
both rsa and dsa type signatures with Crypt::OpenSSL. right now only dsa is 
supported. 

=cut
#-----------------------------------------------------------------------------------
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

#------------------------------------------------------------------------------------
=pod

=head2 new(parameter=>"value", ...)

Optional parameters: 

privkey_file=>$privkey_file, # path to your private key file
 password=>$key_password, # NOT IMPLEMENTED, encryption of your 
                         # private key file
 path=>$path_to_qtc_root, # this is where the qtc root directory is 

 privpath=>$obj->{privpath}, # this is information for rsa_keygen, 
                            # it tells you to which path the new 
                            # key should be put to
 call=>$obj->{call}, # this is also for rsa_keygen, it tells you the call for 
                    # which the key is generated

 dsa_keygen=>1, or rsa_keygen=>1, # if either rsa_keygen or dsa_keygen is set to 1 
                                 # a key will be automatically generated 
											# during object creation, right now only rsa is 
                                 # implemented

Returns: a qtc::signature object

This creates a signature object. 

=cut
#------------------------------------------------------------------------------------
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

#------------------------------------------------------------------------------------
=pod

=head2 rsa_keygen()

Creates a new rsa private key. This is triggered from new() method.  

=cut
#------------------------------------------------------------------------------------
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



#------------------------------------------------------------------------------------
=pod

=head2 sign($msg)

This signs a qtc::msg ogject. It will die in failure. 

=cut
#------------------------------------------------------------------------------------
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
		my $dsa=Crypt::OpenSSL::DSA->read_priv_key_str($obj->{privkey}) or die "Can't read use private key\n"; 
		$msg->signature(
			unpack("H*", 
				$dsa->sign(
					pack("H*", substr(sha256_hex($msg->signed_content_bin), 0, 40))
				)
			), 
			$obj->{key_id}
		); 
	}

}

#------------------------------------------------------------------------------------
=pod

=head2 verify($signed_content_bin, $signature, $signature_key_id)

This is to verify a signature of a qtc::msg object, you put the 
required arguments from the message object into the arguments of 
the method.

It returns 0 on fail or 1 on succsess, on critical issues, it dies.  

Maybe I will consider adding the possibility to do verify($msg) 
in the future. 

=cut
#------------------------------------------------------------------------------------
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

		my $dsa=Crypt::OpenSSL::DSA->read_pub_key_str($obj->prepare_rsa_pubkey($pubkey->key)) or die "Can't read use private key\n"; 
		my $valid=$dsa->verify(
			pack("H*", substr(sha256_hex($msg->signed_content_bin), 0, 40)),
			$signature,
		);
		if ( $valid ) { return 1; }

	}
	return 0; 
}

#------------------------------------------------------------------------------------
=pod

=head2 prepare_rsa_key($key)

This is an internal function to build a base64 encoded readable text string for 
Crypt::OpenSSL::RSA out of the hexadecimal representation of the key data. 

returns: loadable key skalar. 

=cut
#------------------------------------------------------------------------------------
sub prepare_rsa_pubkey {
	my $obj=shift; 
	my $key=shift; 
	return "-----BEGIN RSA PUBLIC KEY-----\n".encode_base64(pack("H*", $key))."-----END RSA PUBLIC KEY-----\n"
}

#------------------------------------------------------------------------------------
=pod

=head2 prepare_dsa_key($key)

This is an internal function to build a base64 encoded readable text string for 
Crypt::OpenSSL::DSA out of the hexadecimal representation of the key data. 

returns: loadable key skalar. 

=cut
#------------------------------------------------------------------------------------
sub prepare_dsa_pubkey {
	my $obj=shift; 
	my $key=shift; 
	return "-----BEGIN DSA PUBLIC KEY-----\n".encode_base64(pack("H*", $key))."-----END DSA PUBLIC KEY-----\n"
}

1; 
=pod

=head1 AUTHOR

Hans Freitag <oe1src@oevsv.at>

=head1 LICENCE

GPL v3

=cut
