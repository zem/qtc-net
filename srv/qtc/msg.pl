package qtc::msg; 
#use POSIX qw(strftime);

our %msg_types=(
	# this is the message itself with required fields
	msg=>{
		"msg_date"=>sub { }, 
		"msg_serial"=>sub { }, 
		"from"=>sub {}, 
		"to"=>sub { }, 
		"via"=>sub { }, 
		"msg"=>sub {}
	}, 
	# this is the qsp info where data is stored
	qsp=>["qsl_date", "qsl_serial", "msg_date", "msg_serial", "via", "log_reference"], 
	# aliases and delivery lists 
	alias=>["call", "alias"], 
	list=>["list", "call"], 
	# keystorage
	pubkey=>["call", "key"],
	revoke=>["call", "key"],
	# trust and untrust users 
	trust=>["trusted_call"],
	suspect=>["suspected_call"],
);



sub new { my $class=shift; my %parm=(@_); return bless $class, $parm; }

sub rcvd_date {
	my $obj=shift;
	my $t=shift; 
	if ( $t ) { 
		if ( $t !~ /^\d+$/ ) { die "Wrong Number format $t, use unix timestamp"; }
		$obj->{rcvd_date} = $t 
	}
	if ( ! $obj->{rcvd_date} ) {
		$obj->{rcvd_date}=gmtime;
	}
}

sub signature {
	my $obj=shift;

}

sub version {
	my $obj=shift;

}

sub type {
	my $obj=shift;

}

sub get_as_text {
	# TO be implementes
}

1; 
