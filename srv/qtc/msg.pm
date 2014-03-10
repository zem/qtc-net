package qtc::msg; 
#use POSIX qw(strftime);
use Digest::SHA qw(sha256_hex);
use XML::XPath; 

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
}



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
		"msg_serial"=>$valid_integer, 
		"from"=>$valid_call, 
		"to"=>$valid_call, 
		"msg"=>$valid_msg,
	}, 
	# this is the qsp info where data is stored
	qsp=>{
		"qsl_date"=>$valid_date, 
		"qsl_serial"=>$valid_integer, 
		"msg_date"=>$valid_date,
		"msg_serial"=>$valid_integer, 
	}, 
	# aliases and delivery lists 
	operator=>{
		"record_date"=>$valid_date, 
		a"set_of_aliases"=>$valid_callset, 
		"set_of_lists"=>$valid_callset,
	}, 
	# keystorage
	pubkey=>{
		"key_type"=>$valid_rsa_or_dsa,  
		"key"=>sub{},
	},
	revoke=>{
		"key_type"=>$valid_rsa_or_dsa,  
		"key"=>sub{},
	},
	# trust and untrust users 
	trust=>{
		"trustlevel"=>$valid_trustlevel,
	},
);


########################################################
# obviously generic right now
########################################################
sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	if ($obj->{filename}) { 
		# try loading data from file
		$obj->load_file($obj->{filename}); 
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
	# TODO QTC Net Crypto Module
	return ""; 
}

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

sub to_filesystem {
	my $obj=shift; 
	my $target=shift; 
	$obj->is_object_valid;
	my $filename=$obj->type."_".$obj->call."_".$obj->checksum.".xml";
	
	open(WRITE, "> ".$target."/".$filename) or die "cant open $target/$filename\n"; 
	print WRITE $obj->as_xml or die "Can't write data to disk\n"; 
	close(WRITE); 
}


# load data from string or filesystem 
sub load_file {
	my $obj=shift; 
	my $filename=shift; 
	if ( ! $filename ) { die "I need a filename\n"; } 
	my $xml; 	

	open(READ, "< $filename") or die "cant open $filename\n"; 
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
