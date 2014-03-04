package qtc::msg; 
#use POSIX qw(strftime);

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
	if ( ! /^\d+$/ ) { 
		die "The Data $_ does contain values other than numbers\n"; 
	}
}
our $valid_date=sub {
	$valid_integer->($1)
	my $now=gmtime; 
	my $maxtime=$now+(3600*5);
	if ( $date > $maxtime ){ die "This date $_ is somehow more than 5 hours in the future, I don't belive that time is syncronized that bad\n"; }
	my $mintime=$now-(3600*24*120);
	if ( $date < $mintime ){ die "This date $_ is somehow more than 120 days in the past, I don't belive that time is syncronized that bad\n"; }
}
our $valid_call=sub {
	if ( ! /^([A-Z]|[0-9]|\/)+$/ ) {
		die "This call $_ has invalid characters\n"; 
	}
	if ( length > 20 ) { 
		die "This call $_ is more than 20 Characters long. Even EA6/OE1SRC/AM is only 13 characters.\n"; 
	}
	#"TODO: add additional callback\n"; 
}
our $valid_msg=sub {
	if ( ! /^([A-Z]|[0-9]|\/|\.|,|\ )+$/ ) {
		die "This message $_ has invalid characters\n"; 
	}
	if ( length > 300 ) { 
		die "This message $_ is more than 300 Characters long.\n"; 
	}
}
our $valid_callset=sub {
	foreach my $call (split(/\ /, $_)) { $valid_call->($call); }
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
		"via"=>$valid_call, 
		"msg"=>$valid_msg,
	}, 
	# this is the qsp info where data is stored
	qsp=>{
		"qsl_date"=>$valid_date, 
		"qsl_serial"=>$valid_integer, 
		"msg_date"=>$valid_date,
		"msg_serial"=>$valid_integer, 
		"via"=>$valid_call, 
		"log_reference"=>sub{},
	}, 
	# aliases and delivery lists 
	operator=>{
		"record_date"=>$valid_date, 
		"call"=>$valid_call, 
		"set_of_aliases"=>$valid_callset, 
		"set_of_lists"=>$valid_callset,
	}, 
	# keystorage
	pubkey=>{
		"call"=>$valid_call,
		"type"=>$valid_rsa_or_dsa,  
		"key"=>sub{},
	},
	revoke=>{
		"call"=>$valid_call,
		"type"=>$valid_rsa_or_dsa,  
		"key"=>sub{},
	},
	# trust and untrust users 
	trust=>{
		"trusted_call"=>$valid_call,
	},
	suspect=>{
		"suspected_call"=>$valid_call,
	},
);


########################################################
# obviously generic right now
########################################################
sub new { my $class=shift; my %parm=(@_); return bless $class, $parm; }


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
		$obj->{rcvd_date}=gmtime;
	}
	return $obj->{rcvd_date}
}

################################################
# There is a big TODO here with the signature
# so atm this will be empty 
sub signature {
	my $obj=shift;

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

sub get_as_text {
	# TO be implementes
}

1; 
