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

this object dies in case of any error, the caller should take care of that. 
(with eval {}) ; 

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

our $valid_telegram=sub {
	$_=shift;
	if ( ! /^([a-z]|[0-9]|\/|\.|,|\ |\?)+$/ ) {
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


#------------------------------------------------------------------------------------
=pod

=head2 our %msg_types

this is an object variable that defines how the messages are structured. A look into 
the Source code will help you thith that. A message has fixed fields like call, signature, 
signature_key_id, checksum, type, version as well as some type specific fields depending 
on the value of the type field. Those type specific fields are defined in %msg_types

=cut
#------------------------------------------------------------------------------------
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
		"telegram"=>$valid_telegram,
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
		"trust_date"=>$valid_date,
		"trustlevel"=>$valid_trustlevel,
		"to"=>$valid_call, # it is easier to store the call than to read every key for its ID
		"set_of_key_ids"=>[$valid_checksum],
	},
);


#------------------------------------------------------------------------------------
=pod

=head2 new(parameter=>"value" ...)

Parameters: path=>$path, filename=>$filename, hex=>$hexstring, type=>$msgtype, 
call=>$msgcall....

Returns: a qtc::msg object

The creator function of this object either loads a message with a specific filename 
from the working path ($path) or it creates a message object with the hexadecimal data 
provided in $hexstring. You may also set initial values of the object by addressing them 
directly as parameter/value pairs, (the content should make sense otherwise a later function 
call will fail)

Every parameter can also be set later on by calling its function with a parameter. but 
then it has to be done in the right order (type before specific field). 

=cut
#------------------------------------------------------------------------------------
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

#------------------------------------------------------------------------------------
=pod

=head2 bin()

Returns: the qtc::binary object, connected to this qtc::msg

The qtc::binary object is holding all the function calls to 
parse, and build the qtc-net binary messages, as hex stream. 

=cut
#------------------------------------------------------------------------------------
sub bin { my $obj=shift; return $obj->{bin}; }


#------------------------------------------------------------------------------------
=pod

=head2 signature()

Optional Parameters: $signature, $signature_key_id
both optional and as Big endian Hex

If no parameter is given it will return the hex string 
of the signature, otherwise it will store one into the 
object.
 
=cut
#------------------------------------------------------------------------------------
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

#------------------------------------------------------------------------------------
=pod

=head2 signature_key_id()

Optional Parameters: none
the signature key is is set with the signature call....

It will return the hex string 
of the signature, otherwise it will store one into the 
object.
 
=cut
#------------------------------------------------------------------------------------
sub signature_key_id {
	my $obj=shift;
	return $obj->{signature_key_id}; 
}

#------------------------------------------------------------------------------------
=pod

=head2 checksum()

retures the checksum of the signed_content of the message.
if there is no checksum stored, it will create one. 
be carefull, it will not create any checksum twice, instead 
it will check the existing one and die if there is no match. 

you may also set a checksum with the first parameter. 

=cut
#------------------------------------------------------------------------------------
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

#------------------------------------------------------------------------------------
=pod

=head2 hr_refnum()

this method returns a human readable reference number between 00 and zz
humans may use this to distinguish between several messages, without 
knowing its content. It is calculated out of the checksum, and can not 
be set. this is a 36*36=1296 possibilitys big checksum, well enough. 

=cut
#------------------------------------------------------------------------------------
sub hr_refnum {
	my $obj=shift; 
	my $num1=hex(substr($obj->checksum, 0, 4));
	my $num2=hex(substr($obj->checksum, 4, 4));
	$num1=int(($num1/hex("ffff"))*35.99);
	$num2=int(($num2/hex("ffff"))*35.99);
	if ( $num1 > 9 ) { $num1=chr($num1-10+0x61); }
	if ( $num2 > 9 ) { $num2=chr($num2-10+0x61); }
	return $num1.$num2; 
}

#------------------------------------------------------------------------------------
=pod

=head2 call()

gets and sets the call of the sender of the message. (do not mix up with the 
from of a telegram) 

=cut
#------------------------------------------------------------------------------------
sub call {
	my $obj=shift; 
	my $call=shift; 
	if ($call){
		$valid_call->($call);
		$obj->{call} = $call;
	} 
	return $obj->{call};
}

#------------------------------------------------------------------------------------
=pod

=head2 escaped_call()

filesystems do not support / in filenames (because this distinguishes directorys) 
but callsigns do so we have do exchange every / in a callsign by a - before we can 
put it into any filename or path. 

this is directed to the call2fname() method inherited from qtc::misc object. 

=cut
#------------------------------------------------------------------------------------
sub escaped_call {
	my $obj=shift; 
	return $obj->call2fname($obj->call); 
}


#------------------------------------------------------------------------------------
=pod

=head2 version()

returns the version of the object or checks if the version of the message 
is compatible 

=cut
#------------------------------------------------------------------------------------
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

#------------------------------------------------------------------------------------
=pod

=head2 type()

get or set the message type 

=cut
#------------------------------------------------------------------------------------
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

#------------------------------------------------------------------------------------
=pod

=head2 has_valid_type()

this function checks if the message objects type is valid/known. 
otherwise the programm will die (eval may take care of this) 

=cut
#------------------------------------------------------------------------------------
sub has_valid_type {
	my $obj=shift;
	if ( ! $msg_types{$obj->{type}} ) { die "Unknown Message Type $type 	please set one first \n"; }
}


#------------------------------------------------------------------------------------
=pod

=head2 AUTOLOAD
=head3 parameter($value)
=head3 $r=parameter()

in general a parameter may be called or set via autoloader 
dynamically. so if the message type has a to field, a method to() 
appears so you may use it. 

=cut
#------------------------------------------------------------------------------------
our $AUTOLOAD; 
sub AUTOLOAD {
	my $obj=shift; 
	my $method=$AUTOLOAD =~ s/.*:://r; 
	return $obj->value($method, @_); 
}

=pod

=head3 value($field, ($data))

you may also use the value($field) method to get access to the objects data. 
the advantage is when you do not exactly know which parameter you will call 
while you are programming. 

=cut
#------------------------------------------------------------------------------------
sub value {
	my $obj=shift; 
	my $method=shift; 
	$obj->has_valid_type; 
	# shortcuts for the static fields 
	if ( $method eq "type" ) { return $obj->type(@_); }
	if ( $method eq "version" ) { return $obj->version(@_); }
	if ( $method eq "call" ) { return $obj->call(@_); }
	if ( $method eq "checksum" ) { return $obj->checksum(@_); }
	if ( $method eq "signature" ) { return $obj->signature(@_); }
	if ( $method eq "signature_key_id" ) { return $obj->signature_key_id(@_); }
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

#------------------------------------------------------------------------------------
=pod

=head3 is_object_valid()

This parameter checks the whole objects data including the checksums if it seems
to be plausible. otherwise it will cause death. So if there is an invalid caracter 
in a callsign or in a hex string, this is the function that raises an error. 

=cut
sub is_object_valid {
	my $obj=shift; 
	$obj->has_valid_type; 
	$valid_call->($obj->{call}); 
	foreach my $field (keys %{$msg_types{$obj->{type}}}) {
		#DEBUG print STDERR $field."\n" ;
		$obj->is_field_valid($field); 
	}
}

#------------------------------------------------------------------------------------
=pod

=head3 is_field_valid($field)

like the is_object_valid() is_field_valid() checks a specific field for 
syntactical validity. it is called by is_object_valid() for each field. 

=cut
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
#------------------------------------------------------------------------------------
=pod

=head3 signed_content_hex()

This function returns the part of the qtc::msg that is going to be signed or 
verified as big endian hex. 

the signed content contains "type", "call" and the alphabetically sorted fields 
of the message, packed together like they would be in the data file. 
  
=cut
sub signed_content_hex {
	my $obj=shift; 
	$obj->is_object_valid;
	return $obj->bin->gen_hex_payload("type", "call", sort keys %{$msg_types{$obj->{type}}});
}

=pod

=head3 signed_content_bin()

like signed_content_hex() but the return of this function is pure binary, this is really 
what is to be signed, just in case someone has the idea to read a qtc::msg with C. 

=cut
sub signed_content_bin {
	my $obj=shift; 
	return pack("H*", $obj->signed_content_hex);
}

=pod

=head3 as_hex()

this returns a hexadecimal Big endian encoded string that contains the complete message 
including a signature. The String can be pack() 'ed and written to disk, or maybe used 
otherwise. 

=cut
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


=pod

=head3 filename()

this returns a standarized filename of the qtc::msg the filename is unique across 
the whole network in the form: type_call_checksum.qtc This means easy lookup for 
most of the messages. 

=cut
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

=pod

=head3 to_filesystem($path)

writes an object down to the configured path in the Filesystem, using the filename() methods 
filename.  The object remembers the configured path so other files may later been hardlinked 
from this one. 

The File is first written as .tmp file and renamed after the write operation is compleded to 
avoid filewatchers using them while they are incomplete. 

=cut
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



=pod

=head3 link_to_path($path)

links the qtc::msg file written by  to_filesystem() to another path, or a set of 
paths. 

=cut
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

=pod

=head3 unlink_at_path($path)

unlinks the qtc::msg file at the given path, or set of 
paths. 

=cut
sub unlink_at_path {
	my $obj=shift;
	foreach my $path (@_) {
		if ( -e $path."/".$obj->filename ) {
			unlink($path."/".$obj->filename) or die "I cant unlink this file to $path\n"; 
		}
	}
}

=pod

=head3 load_file($path, $filename)

loads a file to the object

=cut
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

=pod

=head1 AUTHOR

Hans Freitag <oe1src@oevsv.at>

=head1 LICENCE

GPL v3

=cut

