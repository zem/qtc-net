package qtc::publish; 
use File::Basename; 
use qtc::msg; 
use qtc::signature;
use qtc::misc; 
@ISA=("qtc::misc"); 


# this package provides methods that deliver 
# specific messages.....

sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	if ( ! $obj->{path} ) { $obj->{path}=$ENV{HOME}."/.qtc"; }
	if ( ! $obj->{privpath} ) { $obj->{privpath}=$ENV{HOME}."/.qtc_private"; }
	if ( ! $obj->{privkey_file} ) {
		my @keyfiles=$obj->scan_dir($obj->{privpath}, '((rsa)|(dsa))_.+.key');
		$obj->{privkey_file}=$obj->{privpath}."/".$keyfiles[0]; 
	}
	if ( ! $obj->{call} ) {
		my $call=basename($obj->{privkey_file}); 
		$call=s/^rsa_([0-9]|[a-z]|\-)+_.+.key$/$1/gex;
		$call=s/\-/\//g;
		$obj->{call}=$call;
	}
	if ( ! $obj->{signature} ) { 
		$obj->{signature}=qtc::signature->new(
			privkey_file=>$obj->{privkey_file},
		);
	}
	return $obj; 
}

sub sig { 
	my $obj=shift; 
	return $obj->{signature}; 
}

sub telegram {
	my $obj=shift; 
	my %args=(@_); 
	my $msg=qtc::msg->new(
		type=>"telegram",
		call=>$obj->{call},
		telegram_date=>time,
		from=>$args{from}, 
		to=>$args{to},
		telegram=>$args{telegram},
	);
	$obj->sig->sign($msg); 

	$msg->to_filesystem($obj->{path}."/in"); 
}

sub qsp {
	my $obj=shift; 
	my %args=(@_);
	
	my $msg=$args{msg}; # this is a qtc message
	
	my $qsp=qtc::msg->new(
        type=>"qsp",
        call=>$obj->{call},
        qsl_date=>time,
        to=>$args{to},
        telegram_checksum=>$msg->checksum, 
	);
	$obj->sig->sign($qsp); 
	$qsp->to_filesystem($obj->{path}."/in");
}

sub privkey {
	my $obj=shift; 
	my %args=(@_); 

}

sub revoke {
	my $obj=shift; 
	my %args=(@_); 

}

1; 
