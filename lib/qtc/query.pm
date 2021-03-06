#-----------------------------------------------------------------------------------
=pod

=head1 NAME

qtc::query - query for messages in the folder structure

=head1 SYNOPSIS

use qtc::query;

my $query=qtc::query->new(
   path=>$path,
); 
my @result_msg=$query->latest_changes(20); 

=head1 DESCRIPTION

The Query Object implements several querys at the qtc-net Filesysstem 
structure. It may used by local clients in combination with the qtc::publish 
object, to get access to all the QTC net functions. 

=cut
#-----------------------------------------------------------------------------------
package qtc::query; 
use File::Basename; 
use qtc::msg; 
use qtc::keyring; 
use qtc::misc; 
@ISA=("qtc::misc"); 


# this package provides methods that deliver 
# specific messages.....

#-------------------------------------------------------
=pod

=head2 new(parameter=>"value", ...)

Object creator function, returns qtc::query object

Parameter: 
 path=>$path_to_qtc_root,  # required

=cut
#-------------------------------------------------------
sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	if ( ! $obj->{path} ) { $obj->{path}=$ENV{HOME}."/.qtc"; }
	return $obj; 
}

#-------------------------------------------------------
=pod

=head2 latest_changes($number)

Returns the latest $number network changes ordered by time. 

=cut
#-------------------------------------------------------
sub latest_changes { 
	my $obj=shift; 
	my $number=shift; 
	if ( ! $number ) { $number=0; }
	else { $number = $number * -1 }
	
	my @msgs;
	foreach my $file (($obj->scan_dir_ordered_btime($obj->{path}."/out", '.+\.qtc'))[$number..-1]) {
		unshift @msgs, qtc::msg->new(path=>$obj->{path}."/out", filename=>$file); 
	}

	return @msgs; 
}

#-------------------------------------------------------
=pod

=head2 msg_already_exists($msg, [$folder])

returns 1 if the message already exists in the inbound folder of the server 
or in the relative path given as second optional argument

returns 0 otherwise

This is needed to check if a message created with a rolling checksum is 
already known to the server

=cut
#-------------------------------------------------------
sub msg_already_exists { 
	my $obj=shift; 
	my $msg=shift; 
	my $subpath=shift; if ( ! $subpath ) { $subpath="/in"; } 
	
	if ( -e $obj->{path}.$subpath."/".$msg->filename ) { return 1; }

	return 0; 
}

#-------------------------------------------------------
=pod

=head2 telegram_by_refnum($hr_refnum, $call, [$type])

Returns one specific newest telegram that matches the given 
hr_refnum of the call. or undef if such a telegram is not there. 
it will die if the message cant be read. $type defines where to 
look default is timeline because it contains all the messages 
you may want to qsp from a command line. 

=cut
#-------------------------------------------------------
sub telegram_by_refnum { 
	my $obj=shift; 
	my $hr_refnum=shift; 
	my $call=shift; 
	my $type=shift; if ( ! $type ) { $type="timeline"; }
	
	foreach my $file ($obj->scan_dir($obj->{path}."/call/$call/telegrams/$type", 'telegram_.+\.qtc')){
		my $msg=qtc::msg->new(path=>$obj->{path}."/call/$call/telegrams/$type", filename=>$file); 
		if ( $msg->hr_refnum eq $hr_refnum ) { return $msg; } 
	}

	return; 
}

#-------------------------------------------------------
=pod

=head2 telegram_by_checksum($chksum)

Returns one specific telegram that matches the given checksum. 
or undef if the telegram is not there. it will die if the message 
cant be read. 

=cut
#-------------------------------------------------------
sub telegram_by_checksum { 
	my $obj=shift; 
	my $chksum=shift; 
	my $subpath=shift; if ( ! $subpath ) { $subpath="/out"; } 
	
	foreach my $file ($obj->scan_dir($obj->{path}.$subpath, 'telegram_.+_'.$chksum.'\.qtc')){
		return qtc::msg->new(path=>$obj->{path}.$subpath, filename=>$file); 
	}

	return; 
}

#-------------------------------------------------------
=pod

=head2 list_telegrams($call, $type, $anz, $offset)

Returns telegrams for $call where type can be one of 
undef, new, all, sent
if $type is undef all new telegrams are returned. 

$anz and $offset are optional parameters, telling how 
many messages are to be returned at once and which block. 

=cut
#-------------------------------------------------------
sub list_telegrams { 
	my $obj=shift; 
	my $call=$obj->call2fname(shift); 
	my $type=shift; if ( ! $type ) { $type="new"; }
	my $anz=shift; 
	my $offset=shift; if ( ! defined $offset ) { $offset=0; }
	
	$offset=$anz*$offset; 
	my @msgs;
	foreach my $file ($obj->scan_dir_ordered_btime($obj->{path}."/call/$call/telegrams/$type", '.+\.qtc')){
		unshift @msgs, qtc::msg->new(path=>$obj->{path}."/call/$call/telegrams/$type", filename=>$file); 
	}

	if ( $anz ) { 
		return splice(@msgs, $offset, $anz); 
	}

	return @msgs; 
}

#-------------------------------------------------------
=pod

=head2 num_telegrams($call, $type)

Returns the number of telegrans for $call where type can be one of new, all, sent
if $type is ommitted the number of new telegrams is returned. 

=cut
#-------------------------------------------------------
sub num_telegrams { 
	my $obj=shift; 
	my $call=$obj->call2fname(shift); 
	my $type=shift; if ( ! $type ) { $type="new"; }
	
	my @msgs=$obj->scan_dir($obj->{path}."/call/$call/telegrams/$type", '.+\.qtc');

	return $#msgs+1; 
}

#-------------------------------------------------------
=pod

=head2 pubkey_hash($call)

Returns a pubkey hashref for $call

=cut
#-------------------------------------------------------
sub pubkey_hash {
	my $obj=shift;
	my $call=shift; 
	my $keyring=qtc::keyring->new(
		root=>$obj->{path},
		call=>$call,
	);
	return $keyring->keyhash; 
}

#-------------------------------------------------------
=pod

=head2 pubkey_array($call)

Returns a pubkey arrayref for $call

=cut
#-------------------------------------------------------
sub pubkey_array {
	my $obj=shift;
	my $call=shift; 
	my $keyring=qtc::keyring->new(
		root=>$obj->{path},
		call=>$call,
	);
	return $keyring->keys; 
}

#-------------------------------------------------------
=pod

=head2 operator($call)

Returns the latest operator message for $call if any

=cut
#-------------------------------------------------------
sub operator {
	my $obj=shift; 
	my $call=$obj->call2fname(shift); 
	
	foreach my $file ($obj->scan_dir($obj->{path}."/call/$call", 'operator_.+\.qtc')){
		my $msg=qtc::msg->new(path=>$obj->{path}."/call/$call", filename=>$file); 
		return $msg; 
	}

	return; 
}

#-------------------------------------------------------
=pod

=head2 has_operator($call)

Returns 1 if call has an operator message otherwise undef

=cut
#-------------------------------------------------------
sub has_operator {
	my $obj=shift; 
	my $call=$obj->call2fname(shift); 
	
	foreach my $file ($obj->scan_dir($obj->{path}."/call/$call", 'operator_.+\.qtc')){
		return 1; 
	}

	return; 
}

#-------------------------------------------------------
=pod

=head2 get_old_trust(call=>$call)

This returns the trustlevel message that we previously 
published for that call. Just in case that we want to change 
trust and want to know if it is needed first. 

=cut
#-------------------------------------------------------
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
=pod

=head1 AUTHOR

Hans Freitag <oe1src@oevsv.at>

=head1 LICENCE

GPL v3

=cut
