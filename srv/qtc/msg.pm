#-----------------------------------------------------------------------------------
=pod

=head1 NAME

qtc::msg - object class that handles the various qtc-net messages in perl

=head1 SYNOPSIS

use qtc::msg;

my $msg=qtc::msg->new(path=>$ENV{HOME}."/.qtc/call/$call/telegrams/new", filename=>$file);

print "Number: ".$msg->hr_refnum."\n"; 
print "Date:\t".strftime("%Y-%m-%d %H:%M:%S UTC", gmtime($msg->telegram_date))."\n"; 
print "from:\t".$msg->from."\n"; 
print "to:\t".$msg->to."\n"; 
print "text:\t".$msg->telegram."\n"; 

my $qsp=qtc::msg->new(
	type=>"qsp",
	call=>"oe1src",
	qsl_date=>time,
	to=>$to,
	telegram_checksum=>$qtc->checksum, 
);
$signature->sign($qsp); 

$qsp->to_filesystem($ENV{HOME}."/.qtc/in");

=head1 DESCRIPTION

The qtc message holds and verifys all the data of a qtc message (except of the 
signature verification which is done externaly by qtc::signature). Depending on 
the type of a message it has one call for each field name, that you can use to 
set or read the values of a message.

All binary data is usually stored in hexadecimal big endian within the object, 
to make handling with perl easier.

=cut
#-----------------------------------------------------------------------------------

package qtc::msg; 
#use POSIX qw(strftime);
use Digest::SHA qw(sha256_hex);
use qtc::signature; 
use File::Basename; 
use qtc::binary; 
use qtc::misc;
@ISA=(qtc::misc); 

# This is the version of this qtc::msg class, lower version numbers 
# will be accepted higher will be denied. It is Integer. 
our $VERSION=1; 

#####################################################################################################
# sanity ckeck callbacks 
# those function pointers check their first argument if it has a proper format
# if not they will cause death that should be captured as an exception
# they can be used later within the field definitions 
#####################################################################################################
our $valid_integer=sub {
	$_=shift;
	if ( ! /^\d+$/ ) { 
		die "The Data $_ does contain values other than numbers\n"; 
	}
};

our $valid_date=sub {
	$_=shift;
	$valid_integer->($_);
	my $now=time; 
	my $maxtime=$now+(3600*5);
	if ( $_ > $maxtime ){ die "This date $_ is somehow more than 5 hours in the future, $maxtime, I don't belive that time is syncronized that bad\n"; }
	my $mintime=$now-(3600*24*120);
	if ( $_ < $mintime ){ die "This date $_ is somehow more than 120 days in the past, $mintime, I don't belive that time is syncronized that bad\n"; }
};

our $valid_call=sub {
	$_=shift;
	if ( ! /^([a-z]|[0-9]|\/)+$/ ) {
		die "This call $_ has invalid characters\n"; 
	}
	if ( length > 20 ) { 
		die "This call $_ is more than 20 Characters long. Even EA6/OE1SRC/AM is only 13 characters.\n"; 
	}
	#"TODO: add additional callback\n"; 
};

our $valid_msg=sub {
	$_=shift;
	if ( ! /^([a-z]|[0-9]|\/|\.|,|\ )+$/ ) {
		die "This message $_ has invalid characters\n"; 
	}
	if ( length > 300 ) { 
		die "This message $_ is more than 300 Characters long.\n"; 
	}
};

our $valid_callset=sub {
	$_=shift;
	foreach my $call (split(/\ /)) { $valid_call->($call); }
};

our $valid_trustlevel=sub {
	$_=shift;
	if ( ! /^((-1)|1|0)$/ ) { die "Trustlevel $_ can only be integer 1 0 or -1\n"; }
};

our $valid_rsa_or_dsa=sub {
	$_=shift; 
	if ( ! /^(rsa)|(dsa)$/ ) { die "Unknown key type $_, only rsa and dsa are known and allowed\n"; }
};

our $valid_signature_type=sub {
	$_=shift; 
	if ( ! /^(selfsigned)|(regular)$/ ) { 
		die "Unknown signature_type $_, only selfsigned and regular are known and allowed\n"; 
	}
};

our $valid_hex=sub {
	$_=shift; 
	if ( ! /^([a-f]|[0-9])+$/ ) { 
		die "Invalid hexadecimal data $_ \n"; 
	}
};

our $valid_checksum=sub {
	$_=shift; 
	$valid_hex->($_);
	if ( length != 64 ) { 
		die "Invalid checksum length $_ \n"; 
	}
};


################################################################################################
# There are several message types in QTC net, all of them are electronically signed by the 
# sender. 
# Because this class trys to cover all of them, it has a prototyping structure here. 
#
# Basically it is {messagetypename}->¬{fieldname}->{validitycheckptr}
################################################################################################
# or msg_layout
our %msg_types=(
	# this is the message itself with required fields
	telegram=>{
		"telegram_date"=>$valid_date, 
		"from"=>$valid_call, 
		"to"=>$valid_call, 
		"telegram"=>$valid_msg,
	}, 
	# this is the qsp info where data is stored
	qsp=>{
		"qsl_date"=>$valid_date, 
		"telegram_checksum"=>$valid_checksum,
		"to"=>$valid_call,  #the to field is important for lists 
	}, 
	# aliases and delivery lists 
	operator=>{
		"record_date"=>$valid_date, 
		"set_of_aliases"=>[$valid_call], 
		"set_of_lists"=>[$valid_call],
	}, 
	# keystorage
	pubkey=>{
		"key_type"=>$valid_rsa_or_dsa,  
		"key_id"=>$valid_checksum,  
		"key"=>$valid_hex,
	},
	revoke=>{
		"key_type"=>$valid_rsa_or_dsa,  
		"key_id"=>$valid_checksum,  
		"key"=>$valid_hex,
	},
	# trust and untrust users 
	trust=>{
		"trustlevel"=>$valid_trustlevel,
		"set_of_key_ids"=>[$valid_checksum],
	},
);


###################################################
# Data Storage Types
###################################################
# binary
# integer
# string
sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	$obj->{bin}=qtc::binary->new(msg=>$obj);
	if ($obj->{filename} and $obj->{path}) { 
		# try loading data from file
		$obj->load_file($obj->{path}, $obj->{filename}); 
	} elsif ($obj->{hex}) { 
		# try loading data from string
		$obj->bin->parse($obj->{hex}); 
	}
	return $obj; 
}

sub bin { my $obj=shift; return $obj->{bin}; }

########################################################
# The method calls can either set or receive values
#######################################################
sub rcvd_date {
	my $obj=shift;
	my $t=shift; 
	if ( $t ) { 
		$valid_date->($t);
		$obj->{rcvd_date} = $t;
	}
	if ( ! $obj->{rcvd_date} ) {
		$obj->{rcvd_date}=time;
	}
	return $obj->{rcvd_date}
}

################################################
# There is a big TODO here with the signature
# so atm this will be empty 
sub signature {
	my $obj=shift;
	my $signature=shift; 
	my $signature_key_id=shift; 
	if ( ! $signature ) {
		# we may need to sign this object 
		if ( ! $obj->{signature} ) { die "this object is not signed\n"; }
		$valid_hex->($obj->{signature}); 
		return $obj->{signature};
	} else { 
		if ( ! $signature_key_id ) { die "this function call also needs a signature key id\n"; }
		$valid_hex->($signature); 
		$valid_checksum->($signature_key_id); 
		$obj->{signature}=$signature; 
		$obj->{signature_key_id}=$signature_key_id; 
	}
}

sub signature_key_id {
	my $obj=shift;
	return $obj->{signature_key_id}; 
}

# TODO: place a signature verification option here
# This method is called whenever a signature needs 
# to be checked. 

################################################
# There is a big TODO here with the signature
# so atm this will be empty 
sub checksum {
	my $obj=shift;
	my $checksum=shift; 
	$obj->is_object_valid; 
	if ( ! $obj->{checksum} ) {
		if ( $checksum ) { 
			$obj->{checksum}=$checksum; 
		} else {
			$obj->{checksum}=sha256_hex($obj->signed_content_bin);
		}
	} 
	if ($obj->{checksum}!=sha256_hex($obj->signed_content_bin)) {
		die "object checksum mismatch\n"; 
	} 
	return $obj->{checksum}
}

# this is a human readable two digit number to identify 
# this message between 0 and 99. 
sub hr_refnum {
	my $obj=shift; 
	my $num=hex(substr($obj->checksum, 0, 4));
	$num=int(($num/hex("ffff"))*99);
	# fill numberstring with zeros
	while ( length($num) < 2 ) { $num="0".$num; }
	return $num; 
}

##################################################
# This is the users call which is available in 
# any QTC Net Message
################################################## 
sub call {
	my $obj=shift; 
	my $call=shift; 
	if ($call){
		$valid_call->($call);
		$obj->{call} = $call;
	} 
	return $obj->{call};
}

# an escaped call for filesystem purposes
sub escaped_call {
	my $obj=shift; 
	return $obj->call2fname($obj->call); 
}

sub version {
	my $obj=shift;
	my $v=shift; 
	if ($v){
		$valid_integer->($v);
		$obj->{version} = $v;
	} 
	if ( ! $obj->{version}){ $obj->{version}=$VERSION; }
	return $obj->{version};
}

sub type {
	my $obj=shift;
	my $type=shift; 
	if ($type){
		if ( ! $msg_types{$type} ) { die "Unknown Message Type $type \n"; }
		$obj->{type}=$type; 
	}
	$obj->has_valid_type; 
	return $obj->{type}; 
}

# this is an exception to the other validation functions at the top. It checks if the object 
# already has a valid type otherwise no value can be set. 
sub has_valid_type {
	my $obj=shift;
	if ( ! $msg_types{$obj->{type}} ) { die "Unknown Message Type $type 	please set one first \n"; }
}

our $AUTOLOAD; 
sub AUTOLOAD {
	my $obj=shift; 
	my $method=$AUTOLOAD =~ s/.*:://r; 
	return $obj->get($method); 
}

sub get {
	my $obj=shift; 
	my $method=shift; 
	$obj->has_valid_type; 
	# shortcuts for the static fields 
	if ( $method eq "type" ) { return $obj->type; }
	if ( $method eq "version" ) { return $obj->version; }
	if ( $method eq "call" ) { return $obj->call; }
	if ( $method eq "checksum" ) { return $obj->checksum; }
	if ( $method eq "signature" ) { return $obj->signature; }
	if ( $method eq "signature_key_id" ) { return $obj->signature_key_id; }
	# check if the field is valid
	if ( ! $msg_types{$obj->{type}}->{$method} ) { 
		die "Unknown method $method please set one of the known for ".$obj->{type}." \n"; 
	}
	if ( ref($msg_types{$obj->{type}}->{$method}) eq "ARRAY" ) {
		foreach my $dat ( @_ ) {
			# We have to check the validity of the value
			$msg_types{$obj->{type}}->{$method}->[0]->($dat);
			push @{$obj->{$method}}, $dat;
		}
		return @{$obj->{$method}};
	} else {
		if ( $_[0] ) { 
			# We have to check the validity of the value
			$msg_types{$obj->{type}}->{$method}->($_[0]);
			$obj->{$method}=$_[0]; 
		}
		return $obj->{$method};
	}
}

# check every value of the object again. especially if the values are set
sub is_object_valid {
	my $obj=shift; 
	$obj->has_valid_type; 
	$valid_call->($obj->{call}); 
	foreach my $field (keys %{$msg_types{$obj->{type}}}) {
		#DEBUG print STDERR $field."\n" ;
		$obj->is_field_valid($field); 
	}
}

sub is_field_valid {
	my $obj=shift; 
	my $field=shift; 
	$obj->has_valid_type; 

	if ( ref($msg_types{$obj->{type}}->{$field}) eq "ARRAY" ) {
		foreach my $dat (@{$obj->{field}}) { 
			$msg_types{$obj->{type}}->{$field}->[0]->($dat); 
		}
	} else {
		$msg_types{$obj->{type}}->{$field}->($obj->{$field});
	}

}

################################################################
# this is the hexadecimal part of the package that should be signed 
# don't forget to unpack before doing the signature
################################################################
sub signed_content_hex {
	my $obj=shift; 
	$obj->is_object_valid;
	return $obj->bin->gen_hex_payload("type", "call", sort keys %{$msg_types{$obj->{type}}});
}

sub signed_content_bin {
	my $obj=shift; 
	return pack("H*", $obj->signed_content_hex);
}

sub as_hex {
	my $obj=shift; 
	$obj->is_object_valid;
	return $obj->bin->gen_hex_msg(
		"version", 
		"signature", 
		"signature_key_id", 
		"type", 
		"call", 
		sort keys %{$msg_types{$obj->{type}}}
	);
}


sub filename {
	my $obj=shift;
	$obj->is_object_valid;
	
	my $filename=$obj->type."_".$obj->escaped_call."_".$obj->checksum.".qtc";

	if ( ! $obj->{filename} ) { 
		$obj->{filename}=$filename; 
	} else {
		if ( $obj->{filename} ne $filename ) { 
			die "somehow the object filename $obj->{filename} does not match with the generated $filename\n"; 
		}
	}
	return $filename; 
}

sub to_filesystem {
	my $obj=shift; 
	my $path=shift; 
	$obj->is_object_valid;
	my $filename=$obj->filename;
	$obj->{path}=$path; 
	
	open(WRITE, "> ".$path."/.".$filename.".tmp") or die "cant open $path/$filename\n"; 
	print WRITE pack("H*", $obj->as_hex) or die "Can't write data to disk\n"; 
	close(WRITE); 
	link($path."/.".$filename.".tmp", $path."/".$filename) or die "Can't link to path\n"; 
	unlink($path."/.".$filename.".tmp") or die "Can't unlink tmpfile, this should never happen\n"; 
}


sub link_to_path {
	my $obj=shift;
	if ( ! $obj->{path} ) { die "please store object first\n"; }
	foreach my $path (@_) {
		$obj->ensure_path($path); 
		if ( ! -e $path."/".$obj->filename ) {
			link($obj->{path}."/".$obj->filename, $path."/".$obj->filename) or die "I cant link this file to $path\n"; 
		}
	}
}

sub unlink_at_path {
	my $obj=shift;
	foreach my $path (@_) {
		$obj->ensure_path($path); 
		if ( -e $path."/".$obj->filename ) {
			unlink($path."/".$obj->filename) or die "I cant unlink this file to $path\n"; 
		}
	}
}

# load data from string or filesystem 
sub load_file {
	my $obj=shift; 
	my $path=shift; 
	my $filename=shift; 
	if ( ! $path ) { die "I need a path to load a message\n"; }
	if ( ! -e $path ) { die "Path $path does not exist\n"; } 
	$obj->{path}=$path; 
	if ( ! $filename ) { die "I need a filename\n"; } 
	my $bin; 	

	open(READ, "< $path/$filename") or die "cant open $filename\n"; 
	while(<READ>) { $bin.=$_; }
	close(READ); 

	$obj->bin->parse(unpack("H*", $bin)); 
}



1; 
