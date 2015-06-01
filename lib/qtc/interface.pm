#-----------------------------------------------------------------------------------
=pod

=head1 NAME

qtc::interface - This is a parent class for a qtc interface

=head1 SYNOPSIS

 use qtc::interface;
 @ISA=("qtc::interface"); 

 sub new {
	my $obj=shift; 
	my %arg=(@_); 
	$obj=$obj->SUPER::new(%arg);

	$obj->{can_publish}=1; 
	$obj->{can_sync}=1; 

	return $obj; 
 }

=head1 DESCRIPTION

This is the parent class of any QTC interface. Child classes will 
implement all the Physical protocoll logic while they inherit 
some basic method calls as an interface from the parent. 

Or in other words. You may call all the methods from this object, 
no matter if you have a http, rsync, qtcsync or younameit protocol.  

=cut
#-----------------------------------------------------------------------------------
# general interface class 
package qtc::interface; 

#-------------------------------------------------------
=pod

=head2 new(parameter=>"value", ...)

Object creator function, returns qtc::interface object

Parameter: 
 path=>$path_to_qtc_root,  # required if not $HOME/.qtc
 debug=>0 or 1,            # this is 0 if not set. 

=cut
#-------------------------------------------------------
sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	if ( ! $obj->{path} ) { $obj->{path}=$ENV{HOME}."/.qtc"; }
	if ( ! $obj->{debug} ) { $obj->{debug}=0; }
	return $obj; 
}

#-------------------------------------------------------
=pod

=head2 dprint(...)

If debug=>1 this method does a print STDERR @_ otherwise 
it does not print. 

=cut
#-------------------------------------------------------
sub dprint { 
	my $obj=shift; 
	if ( $obj->{debug} ) { print STDERR @_; }
}

#-------------------------------------------------------
=pod

=head2 can_publish()

this returns true if the interface has a publish() method implemented 
otherwise it returns false. The value must be set by child in the objects 
data. 

=cut
#-------------------------------------------------------
sub can_publish { 
	my $obj=shift; 
	return $obj->{can_publish};
}

#-------------------------------------------------------
=pod

=head2 publish(@msg)

This publishes one or more qtc messaged over this interface

=cut
#-------------------------------------------------------
sub publish {
	my $obj=shift; 
	my $msg=shift;

	die "I do not know how to publish a message through this interface\n"; 
}

#-------------------------------------------------------
=pod

=head2 can_sync()

this returns true if the interface has a sync() and sync_upload() method 
implemented otherwise it returns false. The value must be set by child 
in the objects data. 

=cut
#-------------------------------------------------------
sub can_sync { 
	my $obj=shift; 
	return $obj->{can_sync};
}

#-------------------------------------------------------
=pod

=head2 sync_upload("/in")

This method syncs a local path to a remote one. 
(local /out to remote /in)

=cut
#-------------------------------------------------------
sub sync_upload {
	my $obj=shift; 
	my $path=shift;

	die "I do not know how to syncronize upload with new messages through this interface\n"; 
}

#-------------------------------------------------------
=pod

=head2 sync("/out")

This method syncs a remote path to a local one. 
(remote /out to local /in)

=cut
#-------------------------------------------------------
sub sync {
	my $obj=shift; 
	my $path=shift;

	die "I do not know how to syncronize with new messages through this interface\n"; 
}

1; 
=pod

=head1 AUTHOR

Hans Freitag <oe1src@oevsv.at>

=head1 LICENCE

GPL v3

=cut
