#-----------------------------------------------------------------------------------
=pod

=head1 NAME

qtc::binary - implementation of qtc-nets binary file format in perl

=head1 SYNOPSIS

use qtc::binary;

$obj->{bin}=qtc::binary->new(msg=>$obj);

$hexstring=$obj->bin->gen_hex_payload("type", "call", sort keys %{$msg_types{$obj->{type}}});

$hexstring=$obj->bin->gen_hex_msg(
	"version",
	"signature",
	"signature_key_id",
	"type",
	"call",
	sort keys %{$msg_types{$obj->{type}}}
);

$obj->bin->parse(unpack("H*", $bin));

=head1 DESCRIPTION

The qtc::binary class implements everything that is needed to handle 
the data stored in qtc::nets binary message format as described on 
http://www.qtc-net.org/www. 

It is ususally called as subclass of a qtc::msg object, to seperate 
the namespaces of the binary handler functions from the message data. 

If it needs a fields data from the qtc::msg it calls 
$qtc_msg->value($field) on the other hand it is writing data 
directly into the qtc::msg objects hashref.

Within this object also the message names and their corresponding 
counters and data types as defined in qtc_binary_message.txt are 
configured, in the our %data_types hash within this object.  

=cut
#-----------------------------------------------------------------------------------
package qtc::binary; 
#use POSIX qw(strftime);
use Digest::SHA qw(sha256_hex);
use qtc::signature; 
use File::Basename; 
use qtc::misc;
@ISA=(qtc::misc); 


our $magic="qtc"; 

#########################################################################
# enumerations are to order the identification numbers of fields 
# from 0 to n 
#########################################################################
our %data_types=(
	"type"=>{
		enum=>1,
		data_type=>"enumeration",
		values=>[
			"telegram",
			"qsp",
			"operator",
			"pubkey",
			"revoke",
			"trust",
		],
	},
	"version"=>{
		enum=>2,
		data_type=>"integer",
	},
	"call"=>{
		enum=>3,
		data_type=>"string",
	}, 
	"signature"=>{
		enum=>4,
		data_type=>"binary",
	}, 
	"signature_key_id"=>{
		enum=>5,
		data_type=>"binary",
	},
	"checksum"=>{
		enum=>6,
		data_type=>"binary",
	},
	"from"=>{
		enum=>7,
		data_type=>"string",
	}, 
	"to"=>{
		enum=>8,
		data_type=>"string",
	},
	"telegram_date"=>{
		enum=>9,
		data_type=>"integer",
	},
	"telegram"=>{
		enum=>10,
		data_type=>"string",
	},
	"qsp_date"=>{
		enum=>11,
		data_type=>"integer",
	},
	"telegram_checksum"=>{
		enum=>12,
		data_type=>"binary",
	},
	"record_date"=>{
		enum=>13,
		data_type=>"integer",
	}, 
	"set_of_aliases"=>{
		enum=>14,
		data_type=>"string",
		multiple_times=>1,
	}, 
	"set_of_lists"=>{
		enum=>15,
		data_type=>"string",
		multiple_times=>1,
	}, 
	"key_type"=>{
		enum=>16,
		data_type=>"enumeration",
		values=>["rsa", "dsa"],
	}, 
	"key_id"=>{
		enum=>17,
		data_type=>"binary",
	}, 
	"key"=>{
		enum=>18,
		data_type=>"binary",
	}, 
	"trustlevel"=>{
		enum=>19,
		data_type=>"signedinteger",
	},
	"set_of_key_ids"=>{
		enum=>20,
		data_type=>"binary",
		multiple_times=>1,
	},
	"trust_date"=>{
		enum=>21,
		data_type=>"integer",
	},
	"key_date"=>{
		enum=>22,
		data_type=>"integer",
	}, 
);


#------------------------------------------------------------------------------------
=pod

=head2 new(parameter=>"value" ...)

Parameters: msg=>$qtcmsg

Returns: a qtc::binary object

The creator function of this object returns a qtc::binary object. It needs the 
Message object in the Parameter msg=> to know where to save back to or read in the 
parsed values from. 

It is usually also stored within the qtc::message object itself. So both objects 
can access each other. 

=cut
#------------------------------------------------------------------------------------
sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	return $obj; 
}

#------------------------------------------------------------------------------------
=pod

=head2 msg()

Returns: the qtc::msg object connected with this object

=cut
#------------------------------------------------------------------------------------
sub msg { 
	my $obj=shift; 
	return $obj->{msg}; 
}

#------------------------------------------------------------------------------------
=pod

=head2 pull_byte()

example: 
	
($bytestring, $remaininghexstring)=pull_byte($hexstring)

Gets one byte (two characters) from a Hexadecimal big endian 
encoded string and returns the resulting bytestring as wenll 
as the remaining hexstring. 

=cut
#------------------------------------------------------------------------------------
# gets one hexadecimal byte + returns the right part of that string
sub pull_byte {
	my $obj=shift; 
	my $hex=shift; 
	return (substr($hex, 0, 2), substr($hex, 2)); 
}

sub pull_data {
	my $obj=shift;
	my $len=shift;  
	my $hex=shift;
	return (substr($hex, 0, $len*2), substr($hex, $len*2)); 
}

# get the number of a field or its length out of the hex data stream.... 
sub get_key {
	my $obj=shift;
	my ($key, $hex)=$obj->pull_byte(shift);
	# i hope that this is platform independent 
	my $val=unpack("C*", pack("H*", $key));
	if ( $val >= 0x80 ) {
		return $val-0x80, $hex;
	} elsif ( $val >= 0x40 ) {
		($x, $hex)=$obj->pull_byte($hex);
		$key.=$x;
		$val=unpack("S>*", pack("H*", $key))-0x4000;
		return $val, $hex;
	} elsif ( $val >= 0x20 ) {
		($x, $hex)=$obj->pull_byte($hex);
		$key.=$x;
		($x, $hex)=$obj->pull_byte($hex);
		$key.=$x;
		$val=unpack("I>*", pack("H*", $key))-0x200000;
		return $val, $hex;
	} elsif ( $val >= 0x10 ) {
		($x, $hex)=$obj->pull_byte($hex);
		$key.=$x;
		($x, $hex)=$obj->pull_byte($hex);
		$key.=$x;
		($x, $hex)=$obj->pull_byte($hex);
		$key.=$x;
		$val=unpack("I>*", pack("H*", $key))-0x10000000;
		return $val, $hex;
	}
	die "we have a problem here, because a number is larger than we can detect. a better implementation is needed\n";
}

# creates a hexadecimal key (either id or length)  
sub create_key {
	my $obj=shift;
	my $int=shift;
	
	if ( $int < 0x80 ) { 
		# easy
		return unpack("H*", pack("C*", ($int+0x80)));		
	} elsif ( $int < 0x4000 ) {
			return substr(
				unpack(
					"H*", 
					pack("L>*", ($int+0x4000))
				),
				4
			);
	} elsif ( $int < 0x200000 ) {
			return substr(
				unpack(
					"H*", 
					pack("L>*", ($int+0x200000))
				),
				2
			);
	} elsif ( $int < 0x10000000 ) {
		return unpack(
			"H*", 
			pack("L>*", ($int+0x10000000))
		);
	}
	die "we have a problem here, because a number is larger than we can encode. a better implementation is needed\n";
}

sub mk_field {
	my $obj=shift; 
	my $name=shift; 
	my $data=shift; 
	
	if ( ! $data_types{$name} ) { die "data type not specified\n"; }
	my $key=$obj->create_key($data_types{$name}->{enum});
	# encode various data types here
	my $encdata; 
	if ( $data_types{$name}->{data_type} eq "binary") {
		$encdata=$data; 
	} elsif ( $data_types{$name}->{data_type} eq "string" ) {
		$encdata=unpack("H*", $data); 
	} elsif ( $data_types{$name}->{data_type} eq "integer" ) {
		$encdata=$obj->encode_integer($data); 
	} elsif ( $data_types{$name}->{data_type} eq "signedinteger" ) {
		if ( $data < 0 ) { 
			$data=(abs($data)*2)+1;
		} else { 
			$data=($data*2);
		}
		$encdata=$obj->encode_integer($data); 
	} elsif ( $data_types{$name}->{data_type} eq "enumeration" ) {
		$encdata=$obj->encode_integer(
			$obj->get_enumeration_index($data, @{$data_types{$name}->{values}}) 
		); 
	}
	my $len=$obj->create_key(length($encdata)/2);
	return $key.$len.$encdata;	
}

sub encode_integer {
	my $obj=shift; 
	my $data=shift; 
	my $encdata; 
	if ( $data <= 0xFFFFFFFF ) {
		$encdata=unpack("H*", pack("L>*", $data)); 
	} else {
		# TODO: right now this is not working with > 64 bit 
		# integers, we may have to place code there, if we need 
		# numbers bigger than this, right now, even unix dates 
		# can be encoded with this. 
		$encdata=unpack("H*", pack("Q>*", $data));
	}
	# strip leading zeros 
	while ( $encdata =~ /^00/ ) { $encdata=substr($encdata, 2); }
	return $encdata; 
}

sub get_enumeration_index {
	my $obj=shift; 
	my $key=shift; 
	my @values=@_; 
	my $cnt=1;
	foreach my $value (@values) {
		if ( $value eq $key ) { return $cnt; }
		$cnt++;
	}
	die "uups this enumeration value $key does not exists in @values \n"; 
}

sub get_keyname {
	my $obj=shift; 
	my $key=shift; 
	foreach my $k (keys %data_types) {
		if ($data_types{$k}->{enum} == $key ) { return $k; }
	}
	die "uups this enumeration value $key does not exists in %data_types \n"; 
}

sub parse { 
	my $obj=shift;
	my $hex=shift; 

	#print STDERR "$hex\n";

	# first step is to check the magic bytes 
	my $mag1; my $mag2; my $mag3; 
	($mag1, $hex)=$obj->pull_byte($hex);
	($mag2, $hex)=$obj->pull_byte($hex);
	($mag3, $hex)=$obj->pull_byte($hex);
	if ( $mag1.$mag2.$mag3 ne unpack("H*", $magic)) { die "wrong message magic should be qtc\n"; }
	
	# then we check the overall length of a package
	my $len; 
	($len, $hex)=$obj->get_key($hex); 
	if ( $len*2 != length($hex) ) { die "the length of the message does not match with the message\n";}
	
	# now we can go through any of the data, finding the package. 
	while ( $hex ) {
		my $keynum; 
		my $l; 
		my $data; 
		($keynum, $hex) = $obj->get_key($hex); 
		my $keyname=$obj->get_keyname($keynum);
		($l, $hex) = $obj->get_key($hex);
		($data, $hex) = $obj->pull_data($l, $hex);
		#print $data."\n";
		
		if ( $data_types{$keyname}->{data_type} eq "string" ) {
			$data=pack("H*", $data); 
		} elsif ( $data_types{$keyname}->{data_type} eq "binary" ) {
			$data=$data; 
		} elsif ( $data_types{$keyname}->{data_type} eq "integer" ) {
			while ( length($data) < 8 ) { $data="00".$data; }
			$data=unpack("L>*", pack("H*", $data));  # TODO: fix this in 2038 if needed
			#print $data."\n";
		} elsif ( $data_types{$keyname}->{data_type} eq "signedinteger" ) {
			while ( length($data) < 8 ) { $data="00".$data; }
			$data=unpack("L>*", pack("H*", $data));  # TODO: fix this in 2038 if needed
			if ( $data & 1) { 
				$data=($data-1)/(-2);
			} else { 
				$data=$data/2; 
			}
		} elsif ( $data_types{$keyname}->{data_type} eq "enumeration" ) {
			while ( length($data) < 8 ) { $data="00".$data; }
			$data=$data_types{$keyname}->{values}->[unpack("L>*",  pack("H*", $data))-1]; 
		}
		#print STDERR $keyname." ".$data."\n";
		if ( $data_types{$keyname}->{multiple_times} ) { 
			push @{$obj->msg->{$keyname}}, $data; 
		} else {
			$obj->msg->{$keyname}=$data; 
		}
	}
}

sub gen_hex_payload { 
	my $obj=shift;
	my @fields=@_; 
	my $ret; 
	
	foreach my $field (@fields) {
		foreach my $data ($obj->msg->value($field)) {
			$ret.=$obj->mk_field($field, $data);
		} 
	}
	return $ret; 
}	

sub gen_hex_msg { 
	my $obj=shift;
	my @fields=@_; 
	my $ret=$obj->gen_hex_payload(@fields); 
	return unpack("H*", $magic).$obj->create_key((length($ret)/2)).$ret;
}	

1; 
