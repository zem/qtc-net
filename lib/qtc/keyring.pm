#-----------------------------------------------------------------------------------
=pod

=head1 NAME

qtc::keyring - a class that loads a public key ring

=head1 SYNOPSIS

 use qrc::keyring;
 
 $keyring=qtc::keyring->new(
    call=>$call,
    root=>$qtc_root_path,
    keys=>\@additional_keys, 
 );
 my $keyhashref=$keyring->keyhash; 
 my $keysarrayref=$keyring->keys; 


=head1 DESCRIPTION

QTC keyring class is used to load the public key messages of a publisher, into 
an array. It will automatically verify the keys signature, as well as if all 
the other keys are signed by one root key. 

It sorts out the good keys from the bad ones. the goal is that you can realy 
trust the keys that passed through this filter. 

This is not an easy task especially if you are unsure who send that key to you,
that means it will have some bugs, and design flaws. 

=cut
#-----------------------------------------------------------------------------------
package qtc::keyring; 
use qtc::msg; 
use qtc::signature; 
use File::Basename; 
use Data::Dumper; 
use qtc::misc;
@ISA=(qtc::misc);

=head2 new(parameter=>"value", ...)

The object creator method. returns a qtc keyrink object. 

Parameters:
 root    to set the qtc base dir 
 call    to set the call for which the keys should be loaded
 keys    is an arrayref that contains additional keys to be 
         added to the ring

The object holds several data structures: 

=head3 $obj->{tree}={}

This represents a signature tree in the following form: 

 $obj->{tree}->{$key_id}->{key_obj}=$pubkey_msg
 $obj->{tree}->{$key_id}->{$signed_key_id}->{key_obj}=$another_pubkey_msg

and so on. We use this to get all the public keys a user may have in order. 

=head3 $obj->{keys}=[]

This array initially holds all public keys. You may add some from the outside, 
just in case you are a processor and you want to verify a self signed public key 
for the first time you see it. 

keys will be deleted later during object creation and replaced with a validated 
set of keys. 

=head3 $obj->{keyhash}={}

The keyhash holds a flat reference: $obj->{keyhash}->{$key_id}=$key_obj this 
provides a much faster lookup than looping through arrays every time. 

=cut
# this package does all the linking of a qtc-net message to its right folders 
sub new { 
   my $class=shift; 
   my %parm=(@_); 
   my $obj=bless \%parm, $class; 
	if ( ! $obj->{root} ) { 
		$obj->{root}=$ENV{HOME}."/.qtc"; 
	}
	if ( ! $obj->{call} ) { 
		die "You gave me no call to load the keyring\n"; 
	}
	if ( ! $obj->{tree} ) { 
		$obj->{tree}={};
	}
	if ( ! $obj->{keys} ) { 
		$obj->{keys}=[];
	}
	if ( ! $obj->{keyhash} ) { 
		$obj->{keyhash}={};
	}
	$obj->load_keys; 
	$obj->validate_tree; 
   return $obj; 
}

#---------------------------------------------------------
=pod

=head2 load_keys()

Is called by new() 

This loads all the keys from the calls pubkey directory 
into the keys arrayref, it will then build the key tree by calling 
the build_tree() method. 

=cut
#---------------------------------------------------------
sub load_keys {
	my $obj=shift;
	my $path=$obj->{root}."/call/".$obj->call2fname($obj->{call})."/pubkey";
	$obj->ensure_path($path); 
	foreach my $filename (
		$obj->scan_dir(
			$path,
			'.*\.qtc',
		) 
	) {
			my $key=qtc::msg->new(path=>$path, filename=>$filename);
			push @{$obj->{keys}}, $key;
	}
	foreach my $key (@{$obj->{keys}}) {
		if ( $key->key_id eq $key->signature_key_id ) {
			# this key is self signed and therefor it is a root key
			$obj->{tree}->{$key->key_id}->{key_obj}=$key; 
		}
	}
	$obj->{selfsigned_to_delete}=[]; 
	foreach my $key_id (keys %{$obj->{tree}}) {
		#print STDERR "build_tree $key_id\n"; 
		$obj->build_tree($obj->{tree}->{$key_id});
	}
	# delete all selfsigned trees that are connected elsewhere
	while (my $key_id=shift(@{$obj->{selfsigned_to_delete}})) {
		delete($obj->{tree}->{$key_id});
	}

}

#---------------------------------------------------------
=pod

=head2 grep_signed_by($key_id)

returns an array of keys signed by the key_id given as parameter

=cut
#---------------------------------------------------------
sub grep_signed_by {
	my $obj=shift; 
	my $key_id=shift; 

	my @ret; 
	foreach my $key (@{$obj->{keys}}) {
		if ( $key->signature_key_id eq $key_id ) {
			push @ret, $key; 
		}
	}
	return @ret; 
}

#---------------------------------------------------------
=pod

=head2 build_tree($tree_hashref)

this builds the tree as described in new(), it wants a 
hashref pointing to the level that is currently build, and 
it will call itself recursively for every sublevel. 

=cut
#---------------------------------------------------------
sub build_tree {
	my $obj=shift; 
	my $hashref=shift; 
	
	#print STDERR "Build tree called with: ".Dumper($hashref);
	#die "uargg"; 

	foreach my $key ($obj->grep_signed_by($hashref->{key_obj}->key_id)) {
		$hashref->{$key->key_id}->{key_obj}=$key;
		if ($key->key_id ne $key->signature_key_id ) {
			# if the key is not self signed we can store this Key ID for later deletion
			push @{$obj->{selfsigned_to_delete}}, $key->key_id;
			# key deletion is done in load_keys()
			# we can also build a subtree selfsigned keys are ignored if they are not in the tree root
			$obj->build_tree($hashref->{$key->key_id});
		} 
	}
}

#---------------------------------------------------------
=pod

=head2 validate_tree()

This validates the whole tree structure, that means it checks 
every signature and delets every invalid tree segments. It calls 
valitate_subtree() for every subtree. 

=cut
#---------------------------------------------------------
sub validate_tree {
	my $obj=shift;

	my @tree=keys %{$obj->{tree}};
	if ( $#tree > 0 ) { 
		# die "There is more than one root in our Tree this can't be\n";  this was one the message 
		# that was send here, however we can have more than one key. 
		# 
		# we will return the older tree here, this is a bit of a prob because you can "overtake" 
		# a call but building a real blockchain causes other probs. And I can't use my trustlevels here either 
		# because the trust is not there when I make the decision. so I may go with an additional 
		# Proof of Work concept here in the future.
		my $old_key_date=time+86400; # I hope your system clock is well set  
		my $old_key_id; # I hope your system clock is well set  
		foreach my $key_id (@tree) {
			my $key_date=$obj->{tree}->{$key_id}->{key_obj}->key_date;
			if ( $old_key_date >  $key_date ) {
				if ( $old_key_id ) { 
					delete $obj->{tree}->{$old_key_id};
					$old_key_date=$key_date; 
					$old_key_id=$key_id;  
				}
			} elsif ( $old_key_date <  $key_date ) {
				delete $obj->{tree}->{$key_id}; 
			} elsif ( $old_key_date == $key_date ) {
				# I know this is not right but, lets drop both of them until we have pow to decide
				if ( $old_key_id ) { delete $obj->{tree}->{$old_key_id}; }
				delete $obj->{tree}->{$key_id}; 
				$old_key_date=$key_date; 
				$old_key_id='';
			}
		}	
	}
	if ( $#tree == -1 ) { 
		print STDERR Dumper($obj);
		die "Uuuuuuups there are no keys there for $obj->{call}\n";
	}
	if ( $#tree > 0 ) { 
		die "There is more than one root in our Tree this can't be\n";  
	}

	# ok here we are
	$obj->{keys}=[]; 
	foreach my $key_id (keys %{$obj->{tree}}) { $obj->{tree}->{key_obj}=$obj->{tree}->{$key_id}->{key_obj}; }
	$obj->validate_subtree($obj->{tree})
}

#---------------------------------------------------------
=pod

=head2 validate_subtree($hashref)

This validates a subtree of the tree structure, that means it checks 
every signature and delets every invalid tree segments. It calls 
valitate_subtree() recursively for every subtree. 

=cut
#---------------------------------------------------------
sub validate_subtree {
	my $obj=shift;
	my $hashref=shift; 
	
	if ( ! $hashref->{key_obj} ) { die "uargh no key_obj in the subtree horrorbly wrong\n"; }
	my @key_ids=grep(!/^key_obj$/, keys %$hashref);

	my $signature=qtc::signature->new(
		pubkey=>{
			$hashref->{key_obj}->key_id => $hashref->{key_obj}
		},
	);

	foreach my $key_id (@key_ids) {
		my $key=$hashref->{$key_id}->{key_obj}; 
		my $return=$signature->verify($key->signed_content_bin, $key->signature, $key->signature_key_id);
		if ( ! $return ) { die "Key with checksum ".$key->checksum." could not be verified\n"; }
		push 	@{$obj->{keys}}, $key;
		$obj->{keyhash}->{$key->key_id}=$key;
		$obj->validate_subtree($hashref->{$key_id});
	}
	
}

#---------------------------------------------------------
=pod

=head2 keyhash()

returns the keyhash reference to all validated keys.

=cut
#---------------------------------------------------------
sub keyhash {
	my $obj=shift; 
	return $obj->{keyhash};
}

#---------------------------------------------------------
=pod

=head2 keys()

returns the keyarray reference to all validated keys.

=cut
#---------------------------------------------------------
sub keys {
	my $obj=shift; 
	return $obj->{keys};
}


1; 
=pod

=head1 AUTHOR

Hans Freitag <oe1src@oevsv.at>

=head1 LICENCE

GPL v3

=cut
