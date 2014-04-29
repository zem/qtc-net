package qtc::query; 
use File::Basename; 
use qtc::msg; 
use qtc::keyring; 
use qtc::misc; 
@ISA=("qtc::misc"); 


# this package provides methods that deliver 
# specific messages.....

sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	if ( ! $obj->{path} ) { $obj->{path}=$ENV{HOME}."/.qtc"; }
	return $obj; 
}

sub latest_changes { 
	my $obj=shift; 
	my $number=shift; 
	if ( ! $number ) { $number=0; }
	else { $number = $number * -1 }
	
	my @msgs;
	foreach my $file (($obj->scan_dir_ordered($obj->{path}."/out", '.+\.qtc'))[$number..-1]) {
		unshift @msgs, qtc::msg->new(path=>$obj->{path}."/out", filename=>$file); 
	}

	return @msgs; 
}

sub list_telegrams { 
	my $obj=shift; 
	my $call=$obj->call2fname(shift); 
	my $type=shift; if ( ! $type ) { $type="new"; }
	
	my @msgs;
	foreach my $file ($obj->scan_dir($obj->{path}."/call/$call/telegrams/$type", '.+\.qtc')){
		push @msgs, qtc::msg->new(path=>$obj->{path}."/call/$call/telegrams/$type", filename=>$file); 
	}

	return @msgs; 
}

sub num_telegrams { 
	my $obj=shift; 
	my $call=$obj->call2fname(shift); 
	my $type=shift; if ( ! $type ) { $type="new"; }
	
	my @msgs=$obj->scan_dir($obj->{path}."/call/$call/telegrams/$type", '.+\.qtc');

	return $#msgs+1; 
}

sub pubkey_hash {
	my $obj=shift;
	my $call=shift; 
	my $keyring=qtc::keyring->new(
		root=>$obj->{path},
		call=>$call,
	);
	return $keyring->keyhash; 
}

sub pubkey_array {
	my $obj=shift;
	my $call=shift; 
	my $keyring=qtc::keyring->new(
		root=>$obj->{path},
		call=>$call,
	);
	return $keyring->keys; 
}

sub operator {
	my $obj=shift; 
	my $call=$obj->call2fname(shift); 
	
	foreach my $file ($obj->scan_dir($obj->{path}."/call/$call", 'operator_.+\.qtc')){
		my $msg=qtc::msg->new(path=>$obj->{path}."/call/$call", filename=>$file); 
		return $msg; 
	}

	return; 
}

# receive an old trust message for a call 
sub get_old_trust {
	my $o=shift; 
	my %p=@_; 
	
	foreach my $file (
		$o->scan_dir(
			$o->{path}."/call/".$o->call2fname($p{call})."/trust", 
			'trust_'.$o->call2fname($p{call}).'_[0-9a-f]+\.qtc'
		)
	){
		my $msg=qtc::msg->new(
			path=>$o->{path}."/call/".$o->call2fname($p{call})."/trust", 
			filename=>$file
		); 
		if ( $msg->to eq $p{to} ) { return $msg; }
	}
	return; 
}

1; 
