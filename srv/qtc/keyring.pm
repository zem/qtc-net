package qtc::keyring; 
use qtc::msg; 
use qtc::signature; 
use File::Basename; 
use Data::Dumper; 
use qtc::misc;
@ISA=(qtc::misc);

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

sub load_keys {
	my $obj=shift;
	my $path=$obj->{root}."/call/".$obj->call2fname($obj->{call})."/pubkey";
	$obj->ensure_path($path); 
	foreach my $filename (
		$obj->scan_dir(
			$path,
			'.*\.xml',
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
		$obj->build_tree($obj->{tree}->{$key_id});
	}
	# delete all selfsigned trees that are connected elsewhere
	while (my $key_id=shift(@{$obj->{selfsigned_to_delete}})) {
		delete($obj->{tree}->{$key_id});
	}

}

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

sub validate_tree {
	my $obj=shift;

	my @tree=keys %{$obj->{tree}};
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
		my $return=$signature->verify($key->signed_content_xml, $key->signature, $key->signature_key_id);
		if ( ! $return ) { die "Key with checksum ".$key->checksum." could not be verified\n"; }
		push 	@{$obj->{keys}}, $key;
		$obj->{keyhash}->{$key->key_id}=$key;
		$obj->validate_subtree($hashref->{$key_id});
	}
	
}

sub keyhash {
	my $obj=shift; 
	return $obj->{keyhash};
}

sub keys {
	my $obj=shift; 
	return $obj->{keys};
}


1; 
