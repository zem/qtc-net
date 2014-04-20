package qtc::publish; 
use File::Basename; 
use qtc::msg; 
use qtc::signature;
use qtc::query;
use qtc::misc; 
@ISA=("qtc::misc"); 


# this package provides methods that deliver 
# specific messages.....

sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	if ( ! $obj->{path} ) { $obj->{path}=$ENV{HOME}."/.qtc"; }
	if ( ! $obj->{pidfile} ) { 
		$obj->{pidfile}=$obj->{path}."/.qtc_processor.pid";
	}
	if ( ! $obj->{privpath} ) { $obj->{privpath}=$ENV{HOME}."/.qtc_private"; }
	if ( ! $obj->{privkey_file} ) {
		my @keyfiles=$obj->scan_dir($obj->{privpath}, '((rsa)|(dsa))_.+.key');
		$obj->{privkey_file}=$obj->{privpath}."/".$keyfiles[0]; 
	}
	if ( ! $obj->{call} ) {
		my $call=basename($obj->{privkey_file}); 
		$call=~s/^((rsa)|(dsa))_(([0-9]|[a-z]|\-)+)_([0-9]|[a-f])+.key$/$4/ge;
		$call=~s/\-/\//g;
		$obj->{call}=$call;
	}
	if ( ! $obj->{call} ) { die "we still don't have a call so we cant continue\n"; }
	if ( ! $obj->{query} ) { 
		$obj->{query}=qtc::query->new(
			path=>$obj->{path},
		);
	}
	if ( ! $obj->{signature} ) { 
		$obj->{signature}=qtc::signature->new(
			privkey_file=>$obj->{privkey_file},
			password=>$obj->{password},
			
			path=>$obj->{path}, 
			privpath=>$obj->{privpath}, 
			call=>$obj->{call},
			
			dsa_keygen=>$obj->{dsa_keygen},
			rsa_keygen=>$obj->{rsa_keygen},
		);
	}
	return $obj; 
}

# ok you may ask, "why this, here?!?" 
# it is because the privpath is well known to this module
sub get_public_key_msg {
	my $obj=shift; 
	my @files=$obj->scan_dir($obj->{privpath}, "^pubkey_".$obj->call2fname($obj->{call}).'_[0-9a-f]+.qtc$');
	if ( $#files == -1 ) { die "cant find any public key msg\n"; }
	my $msg=qtc::msg->new(path=>$obj->{privpath}, filename=>$files[0]); 
	return $msg; 
}

sub query { 
	my $obj=shift; 
	return $obj->{query}; 
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
	$obj->wakeup_processor; 
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
	$obj->wakeup_processor; 
}

sub pubkey {
	my $obj=shift; 
	my %args=(@_); 

	my $qtc=qtc::msg->new(hex=>$args{hex});
	$qtc->drop_checksum; 
	$qtc->key_date(time); 
	$obj->sig->sign($qtc);
	$qtc->to_filesystem($obj->{path}."/in");
	$obj->wakeup_processor; 
}

sub revoke {
	my $obj=shift; 
	my %args=(@_); 

	my $pubkey;
	if ( $args{hex} ) {
		$pubkey=qtc::msg->new(hex=>$args{hex});
	} else {
		$pubkey=$obj->get_public_key_msg(); 
	}	

	my $qtc; 

	if ( $pubkey->type  eq "revoke" ) { # this already is a revoke 
		$qtc=$pubkey; 
	} else {
		$qtc=qtc::msg->new(
			call=>$obj->{call},
			type=>"revoke",
			key_type=>$pubkey->key_type,
			key_id=>$pubkey->key_id,
			key=>$pubkey->key,
		); 
		$obj->sig->sign($qtc);
	}
	
	if ($qtc->key_id ne $obj->signature_key_id) { die "Revokes must be published by key owner\n"; }

	if ( $args{download} ) { 
		return $qtc->as_hex; 
	} else {
		$qtc->to_filesystem($obj->{path}."/in");
		$obj->wakeup_processor;
	}
}

sub operator {
	my $obj=shift; 
	my %args=(@_); 

	$qtc=qtc::msg->new(
		call=>$obj->{call},
		type=>"operator",
		record_date=>time,
		set_of_aliases=>$args{set_of_aliases},
		set_of_lists=>$args{set_of_lists},
	); 
	
	$obj->sig->sign($qtc); 
	$qtc->to_filesystem($obj->{path}."/in");
	$obj->wakeup_processor; 
}

sub trust {
	my $obj=shift; 
	my %args=(@_); 
	
	$qtc=qtc::msg->new(
		call=>$obj->{call},
		type=>"trust",
		trust_date=>time,
		to=>$args{to},
		set_of_key_ids=>[keys $obj->query->pubkey_hash($args{to})],
		trustlevel=>$args{trustlevel},
	); 
	
	$obj->sig->sign($qtc); 
	$qtc->to_filesystem($obj->{path}."/in");
	$obj->wakeup_processor; 
}

1; 
