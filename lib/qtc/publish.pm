#-----------------------------------------------------------------------------------
=pod

=head1 NAME

qtc::publish - methods to help you to messages to qtc-net

=head1 SYNOPSIS

 use qtc::publish;
 
 my $publish=qtc::publish->new(
   path=>$path,
   privpath=>$directory_where_private_key_is,
 ); 
 $publish->telegram(
   from=>"oe1src",
	to=>"dd5tt",
	telegram=>"hello me",
 );

=head1 DESCRIPTION

This object class provides helper functions to publish messages in the 
qtc-net. It needs a private key file lying around in a privpath directory 
together with its self signed public key message.

It needs as well the path to the qtc net filesystem structure. 

=cut
#-----------------------------------------------------------------------------------
package qtc::publish; 
use File::Basename; 
use qtc::msg; 
use qtc::signature;
use qtc::query;
use qtc::misc; 
@ISA=("qtc::misc"); 


#-------------------------------------------------------
=pod

=head2 new(parameter=>"value", ...)

Object creator function, returns qtc::publish object

Parameter: 
 path=>$path_to_qtc_root,  # required
 privpath=>$directory_where_private_key_is,  # required
 pidfile=>$processor_pid, # optional, defaults within the 
                          # path/.qtc_processor.pid
 privkey_file=>$keyfile   # optional, if the filename cant 
                          # be automaticaly detected

=cut
#-------------------------------------------------------
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


#-------------------------------------------------------
=pod

=head2 get_public_key_msg()

returns the public key message, of the publisher. this method is placed in 
the publish module, because this module well knows the privpath where the 
message can be found. 

=cut
#-------------------------------------------------------
# ok you may ask, "why this, here?!?" 
# it is because the privpath is well known to this module
sub get_public_key_msg {
	my $obj=shift; 
	my @files=$obj->scan_dir($obj->{privpath}, "^pubkey_".$obj->call2fname($obj->{call}).'_[0-9a-f]+.qtc$');
	if ( $#files == -1 ) { die "cant find any public key msg\n"; }
	my $msg=qtc::msg->new(path=>$obj->{privpath}, filename=>$files[0]); 
	return $msg; 
}

#-------------------------------------------------------
=pod

=head2 query()

returns a qtc::qwuery object

=cut
#-------------------------------------------------------
sub query { 
	my $obj=shift; 
	return $obj->{query}; 
}

#-------------------------------------------------------
=pod

=head2 sig()

returns a qtc::signature object

=cut
#-------------------------------------------------------
sub sig { 
	my $obj=shift; 
	return $obj->{signature}; 
}

#-------------------------------------------------------
=pod

=head2 telegram(parameter=>"value", ...)

publishes a telegram

parameters: 
 to=>$to_call,
 from=>$from_call,
 telegram=>$telegram_text,

=cut
#-------------------------------------------------------
sub telegram {
	my $obj=shift; 
	my %args=(@_); 
	$obj->publish_telegram(
		$obj->create_telegram(%args)
	); 
}

#-------------------------------------------------------
=pod

=head2 create_telegram(parameter=>"value", ...)

split of telegram() method into steps 
creates a telegram and returns it. 

parameters: 
 to=>$to_call,
 from=>$from_call,
 telegram=>$telegram_text,
 [checksum_period=>$seconds],
 [qsp_timeout=>$ts_where_msg_is_trated_as_qsped], 
 [telegram_expire=>$ts_when_msg_expires], 
 [set_of_references=>[$reply_to_reference1, $reference2, ...]],

=cut
#-------------------------------------------------------
sub create_telegram {
	my $obj=shift; 
	my %args=(@_); 
	
	my $references=[]; 
	if ( $arg{set_of_references} ) { $references=$arg{set_of_references}; }

	my $timeouts=[];
	if (($args{telegram_expire}) and ( ! $args{qsp_timeout})){$args{qsp_timeout}=$args{telegram_expire};}
	if ( $args{qsp_timeout} ) {
		push @$timeouts, $args{qsp_timeout};
		if ( $args{telegram_expire} ) {
			push @$timeouts, $args{telegram_expire};
		}
	} 

	my $msg=qtc::msg->new(
		type=>"telegram",
		call=>$obj->{call},
		telegram_date=>time,
		from=>$args{from}, 
		to=>$args{to},
		telegram=>$args{telegram},
		checksum_period=>$args{checksum_period},
		set_of_qsp_timeouts=>$timeouts,
		set_of_references=>$references,
	);
	$obj->sig->sign($msg); 

	return $msg; 
}

#-------------------------------------------------------
=pod

=head2 publish_telegram($msg)

split up of the telegram() method in steps 
publishes the telegram

parameters: 
 $msg   a qtc::msg::object,

=cut
#-------------------------------------------------------
sub publish_telegram {
	my $obj=shift; 
	my $msg=shift; 

	$msg->to_filesystem($obj->{path}."/in");
	$obj->wakeup_processor; 
}



#-------------------------------------------------------
=pod

=head2 qsp(parameter=>"value", ...)

publishes a qsp message

parameters: 
 to=>$to_call,
 msg=>$telegram_qtc_msg_object,
 [set_of_comment=>$some_comment]

=cut
#-------------------------------------------------------
sub qsp {
	my $obj=shift; 
	my %args=(@_);
	
	my $msg=$args{msg}; # this is a qtc message

	my $comment=[]; 
	if ( $args{set_of_comment} ) {
		push @$comment, $args{set_of_comment}; 
	} 
	
	my $qsp=qtc::msg->new(
		type=>"qsp",
		call=>$obj->{call},
		qsp_date=>time,
		to=>$args{to},
		telegram_checksum=>$msg->checksum, 
		set_of_comment=>$comment,
	);
	$obj->sig->sign($qsp); 
	$qsp->to_filesystem($obj->{path}."/in");
	$obj->wakeup_processor; 
}

#-------------------------------------------------------
=pod

=head2 pubkey(parameter=>"value", ...)

publishes a public key  message

parameters: 
 hex=>$pubkey_message_as_hex,

the messages signature is cut of and the message is signed 
with the current public/private key pair. This means you can 
sign any other public key to prove that it is yours. 

=cut
#-------------------------------------------------------
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

#-------------------------------------------------------
=pod

=head2 revoke(parameter=>"value", ...)

publish or download a revoke key  message

parameters: 
 hex=>$pubkey_message_as_hex, # optional
                              # get_local_public key if ommitted
 download=>1,      # if true the revoke key will be returned by this function, 
                   # if false the revoke key will be published

if the key uploaded in hex=>"" is a pubkey, a revoke message will be generated, but, 
the revoke must be self signed. 

if hex=>"" contains a revoke message, that message will be published (or download if download=>1) 

if hex=>"" is empty the current public key will be used. 

=cut
#-------------------------------------------------------
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
	
	if ($qtc->key_id ne $qtc->signature_key_id) { die "Revokes must be published by key owner\n"; }

	if ( $args{download} ) { 
		return $qtc; 
	} else {
		$qtc->to_filesystem($obj->{path}."/in");
		$obj->wakeup_processor;
	}
}

#-------------------------------------------------------
=pod

=head2 operator(parameter=>"value", ...)

publishes an operator  message

parameters: 
 set_of_aliases=>[...],
 set_of_followings=>[...],

This publishes an operator message. the sets are followings of callsigns or 
bulletin calls that are followed by this callsign. 

=cut
#-------------------------------------------------------
sub operator {
	my $obj=shift; 
	my %args=(@_); 

	$qtc=qtc::msg->new(
		call=>$obj->{call},
		type=>"operator",
		record_date=>time,
		set_of_aliases=>$args{set_of_aliases},
		set_of_followings=>$args{set_of_followings},
	); 
	
	$obj->sig->sign($qtc); 
	$qtc->to_filesystem($obj->{path}."/in");
	$obj->wakeup_processor; 
}

#-------------------------------------------------------
=pod

=head2 trust(parameter=>"value", ...)

publishes a trustlevel message

parameters: 
 to=>$to_call,
 trustlevel=>$level, # may be 1, 0 or -1 
 [set_of_comment=>$some_comment]

=cut
#-------------------------------------------------------
sub trust {
	my $obj=shift; 
	my %args=(@_); 
	
	my $comment=[]; 
	if ( $args{set_of_comment} ) {
		push @$comment, $args{set_of_comment}; 
	} 

	$qtc=qtc::msg->new(
		call=>$obj->{call},
		type=>"trust",
		trust_date=>time,
		to=>$args{to},
		set_of_key_ids=>[keys $obj->query->pubkey_hash($args{to})],
		trustlevel=>$args{trustlevel},
		set_of_comment=>$comment,
	); 
	
	$obj->sig->sign($qtc); 
	$qtc->to_filesystem($obj->{path}."/in");
	$obj->wakeup_processor; 
}

1; 
=pod

=head1 AUTHOR

Hans Freitag <oe1src@oevsv.at>

=head1 LICENCE

GPL v3

=cut
