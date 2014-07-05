# general interface class 
package qtc::interface; 

sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	if ( ! $obj->{path} ) { $obj->{path}=$ENV{HOME}."/.qtc"; }
	return $obj; 
}

sub can_publish { 
	my $obj=shift; 
	return $obj->{can_publish};
}

sub publish {
	my $obj=shift; 
	my $msg=shift;

	die "I do not know how to publish a message through this interface\n"; 
}

sub can_sync { 
	my $obj=shift; 
	return $obj->{can_sync};
}

sub sync_upload {
	my $obj=shift; 
	my $path=shift;

	die "I do not know how to syncronize upload with new messages through this interface\n"; 
}
sub sync {
	my $obj=shift; 
	my $path=shift;

	die "I do not know how to syncronize with new messages through this interface\n"; 
}

1; 
