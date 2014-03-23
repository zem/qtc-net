package qtc::msg; 
#use POSIX qw(strftime);
use Digest::SHA qw(sha256_hex);
use XML::XPath; 
use qtc::signature; 
use File::Basename; 
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

our $valid_key=sub {
	$_=shift; 
	if ( ! /-----BEGIN (RSA)|(DSA) PUBLIC KEY-----.+-----END (RSA)|(DSA) PUBLIC KEY-----/s ) { 
		die "Invalid public key format\n"; 
	}
};


################################################################################################
# There are several message types in QTC net, all of them are electronically signed by the 
# sender. 
# Because this class trys to cover all of them, it has a prototyping structure here. 
#
# Basically it is {messagetypename}->¬{fieldname}->{validitycheckptr}
################################################################################################
our %msg_types=(
	# this is the message itself with required fields
	msg=>{
		"msg_date"=>$valid_date, 
		"from"=>$valid_call, 
		"to"=>$valid_call, 
		"msg"=>$valid_msg,
	}, 
	# this is the qsp info where data is stored
	qsp=>{
		"qsl_date"=>$valid_date, 
		"msg_checksum"=>$valid_checksum,
		"to"=>$valid_call,  #the to field is important for lists 
	}, 
	# aliases and delivery lists 
	operator=>{
		"record_date"=>$valid_date, 
		"set_of_aliases"=>$valid_callset, 
		"set_of_lists"=>$valid_callset,
	}, 
	# keystorage
	pubkey=>{
		"key_type"=>$valid_rsa_or_dsa,  
		"signature_type"=>$valid_signature_type,  
		"key"=>$valid_key,
	},
	revoke=>{
		"key_type"=>$valid_rsa_or_dsa,  
		"key"=>$valid_key,
	},
	# trust and untrust users 
	trust=>{
		"trustlevel"=>$valid_trustlevel,
	},
);

sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	if ($obj->{filename} and $obj->{path}) { 
		# try loading data from file
		$obj->load_file($obj->{path}, $obj->{filename}); 
	} elsif ($obj->{xml}) { 
		# try loading data from string
		$obj->load_xml($obj->{xml}); 
	}
	return $obj; 
}


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
	my $skip_verification=shift; 
	
	if ( ! $signature ) {
		# we may need to sign this object 
		if ( ! $obj->{signature} ) { 
			#$obj->{qtc_signature};
		}
	} else { 
		$obj->{signature}=$signature; 
	}
	return $obj->{signature};
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
			$obj->{checksum}=sha256_hex($obj->signed_content_xml);
		}
	} 
	if ($obj->{checksum}!=sha256_hex($obj->signed_content_xml)) {
		die "object checksum mismatch\n"; 
	} 
	return $obj->{checksum}
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
	my $value=shift;
	my $method=$AUTOLOAD =~ s/.*:://r; 
	$obj->has_valid_type; 
	# check if the field is valid
	if ( ! $msg_types{$obj->{type}}->{$method} ) { 
		die "Unknown method $method please set one of the known for ".$obj->{type}." \n"; 
	}
	if ( $value ) { 
		# We have to check the validity of the value
		$msg_types{$obj->{type}}->{$method}->($value);
		$obj->{$method}=$value; 
	}
	return $obj->{method};
}

# check every value of the object again. especially if the values are set
sub is_object_valid {
	my $obj=shift; 
	$obj->has_valid_type; 
	$valid_call->($obj->{call}); 
	foreach my $field (keys %{$msg_types{$obj->{type}}}) {
		$msg_types{$obj->{type}}->{$field}->($obj->{$field});
	}
}

################################################################
# The data that is going to be signed is represented as XML 
# parseable but without namespacing, pi, header and spaces 
# between the elements  even if there may some other 
# message formats available, signatures should always be done 
# in this format.  
################################################################
sub signed_content_xml {
	# TO be implementes
	my $obj=shift; 
	$obj->is_object_valid;
	
	my $ret="<".$obj->{type}.">";
	foreach my $field (sort keys %{$msg_types{$obj->{type}}}) {
		$msg_types{$obj->{type}}->{$field}->($obj->{$field});
		$ret.="<$field>".$obj->{$field}."</$field>"; 
	}
	$ret.="</".$obj->{type}.">";
}

sub as_xml {
	# TO be implementes
	my $obj=shift; 
	$obj->is_object_valid;
	
	my $ret="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
	$ret.="<qtc>\n"; 
	$ret.="<version>".$obj->version."</version>\n";	
	#$ret.="<rcvd_date>".$obj->rcvd_date."</rcvd_date>\n";	
	$ret.="<call>".$obj->call."</call>\n";	
	$ret.="<type>".$obj->type."</type>\n";	
	$ret.="<signature>".$obj->signature."</signature>\n";	
	$ret.="<checksum>".$obj->checksum."</checksum>\n";	
	$ret.=$obj->signed_content_xml."\n"; 
	$ret.="</qtc>\n"; 

	return $ret; 
}

sub filename {
	my $obj=shift;
	$obj->is_object_valid;
	
	my $filename=$obj->type."_".$obj->escaped_call."_".$obj->checksum.".xml";

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
	print WRITE $obj->as_xml or die "Can't write data to disk\n"; 
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
	if ( -e $path ) { die "Path $path does not exist\n"; } 
	$obj->{path}=$path; 
	if ( ! $filename ) { die "I need a filename\n"; } 
	my $xml; 	

	open(READ, "< $path/$filename") or die "cant open $filename\n"; 
	while(<READ>) { $xml.=$_; }
	close(READ); 

	$obj->load_xml($xml); 
}

# load data from string or filesystem 
sub load_xml {
	my $obj=shift; 
	my $xml=shift; 
	print $xml; 
	if ( ! $xml ) { die "I need some xml data \n"; } 
	my $xp=XML::XPath->new(xml=>$xml) or die "can't create XPath object from message\n"; 
	# let us store the common values
	$obj->call($xp->getNodeText("qtc/call")->value());
	$obj->type($xp->getNodeText("qtc/type")->value());
	# we will copy every field then 
	foreach my $field (sort keys %{$msg_types{$obj->type}}) {
		$obj->{$field}=$xp->getNodeText("qtc/".$obj->type."/".$field)->value();
	}
	# as well as checksum and signature 
	$obj->checksum($xp->getNodeText("qtc/checksum")->value());
	$obj->signature($xp->getNodeText("qtc/signature")->value());
	# if we are not dead yet, well done 
}

1; 
