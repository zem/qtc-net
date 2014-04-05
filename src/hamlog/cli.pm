package hamlog::cli; 
use Term::ReadLine;

sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	if ( ! $obj->{appname} ) { $obj->{appname}="HamLog"; }
	if ( ! $obj->{prompt} ) { $obj->{prompt}="HamLog> "; }
	if ( ! $obj->{cmds} ) { $obj->config_cmds; }
	if ( ! $obj->{args} ) { $obj->config_args; }
	if ( ! $obj->{term} ) { $obj->{term}=Term::ReadLine->new($obj->appname); }
	$obj->config_term;
	return $obj; 
}

sub term { return shift->{term}; }
sub appname { return shift->{appname}; }
sub prompt { return shift->{prompt}; }

sub config_args {
	my $obj=shift;
	$obj->{args}={}; 
}

sub config_cmds {
	my $obj=shift;
	$obj->{cmds}={}; 
	$obj->{cmds}->{exit}=1;
	$obj->{cmds}->{quit}=1;
	$obj->{cmds}->{help}=1;
}

sub config_term {
	my $obj=shift; 
	my $attr=$obj->term->Attribs;
	$attr->{completion_entry_function}=sub { return $obj->completition_entry_function(@_); };
}


####################################
# reimplement in child class
sub completition_matches {
	my $obj=shift;
	my $arg=shift; 
	my $numargs=shift; 
	my @cmpl=keys %{$obj->{cmds}};
	if ( $numargs > 0 ) { @cmpl=keys %{$obj->{args}}} 
	my @ret; 
	foreach my $cmd (sort @cmpl) {
		if (substr($cmd, 0, length($arg)) eq $arg) { push @ret, $cmd; }
	}
	return @ret; 
}


sub completition_entry_function {
	my $obj=shift; 
	my $text=shift;
	my $state=shift;
	my @args=$obj->split_line($text); 
	my $numargs=$#args; 
	my @matches=$obj->completition_matches(pop(@args), $numargs);
	#print join(" ", @matches)."--$text--$state\n"; 
	
	my $num=$#matches-$state; 
	if ( $num<0 ) { 
		return undef; 
	} else { 
		return $matches[$num]; 
	}
}


sub loop {
	my $obj=shift; 
	while (1) {
		my $line=$obj->term->readline($obj->prompt); 
		if ( ! $line ) { next; }
		#$obj->term->addhistory($line); 
		#print $line."\n"; 
		my @args=$obj->split_line($line); 
		my $cmd=shift(@args); 
		if ( $obj->{cmds}->{$cmd} ) { 
			eval '$obj->cmd_'.$cmd.'(@args)';
			if ( @_ ) { 
				print "some error occured:\n"; 
				print "@_\n\n"; 
			}
		} else { 
			print "Command $cmd not found/or allowed\n"; 
		}
	}
}


sub split_line {
		my $obj=shift; 
		my $line=shift;

		my $m_str=0; 
		my $m_esc=0; 

		my $x=''; 
		
		my @args; 
		my $chr=" "; 

		while ($chr ne undef) { 
			$chr=substr($line, 0, 1); 
			$line=substr($line, 1); 

			if (( $chr eq "\\" )and (!$m_str)) { 
				if ( $m_esc ) { $m_esc=0; }
				else { 
					$m_esc=1; 
					next; 
				}
			}
			
			if ( $chr eq "\"" ) { 
				if ( $m_str ) { 
					$m_str=0; 
					next; 
				} else { 
					if ( $m_esc ) {
						$m_esc=0; 
					} else {
						$m_str=1; 
						next;
					} 
				}
			} 
			
			if ( $chr=~ /^(\ |\t)$/ ) { 
				if (
					( $x ) and 
					( ! $m_str ) and 
					( ! $m_esc )
				) { 
					push @args, $x; 
					$x=''; 
					next; 
				} elsif ( $m_esc ) { 
					$m_esc=0;
				} elsif ( ! $m_str )  { next; }
			}
			
			# if we are here, we stor the val and go to next char
			$x.=$chr; 
		} 
		
		# if the last param is not yet pushed....
		if ( $x ) { push @args, $x; }

		return @args; 
}

##################################################
sub cmd_quit {
	my $obj=shift; 
	print "Request for program termination\n"; 
	exit; 
}
sub cmd_exit {
	my $obj=shift; 
	$obj->cmd_quit; 
}
sub cmd_help {
	my $obj=shift; 
	print "allowed cmds: ".join(" ", keys %{$obj->{cmds}})."\n"; 
}

1; 
