#-----------------------------------------------------------------------------------
=pod

=head1 NAME

qtc::msg - object class that handles the various qtc-net messages in perl

=head1 SYNOPSIS

use qtc::misc;

my $misc=qtc::misc->new();

or 

@ISA=("qtc::misc"); 

=head1 DESCRIPTION

The qtc::misc objects provides miscellaneous that can be used 
by other qtc librarys. 

Basicly those are methods that are needed in more than one segment 
of the codebase, or that can't be sorted into one segment of the 
code base. 

=cut
#-----------------------------------------------------------------------------------
package qtc::misc; 
use File::Basename; 
use File::ExtAttr ':all';
use POSIX qw(strftime); 

#------------------------------------------------------------------------------------
=pod

=head2 new(parameter=>"value", ...)

Optional parameters: pidfile=>$pid_filename

Returns: a qtc::misc object

This is a generic creator method for an object. If inherited it returns 
the child object, otherwise a qtc::misc one. 

=cut
#------------------------------------------------------------------------------------
sub new { 
	my $class=shift; 
	my %parm=(@_); 
	my $obj=bless \%parm, $class; 
	return $obj; 
}

#------------------------------------------------------------------------------------
=pod

=head2 fname2call()

my $call=$obj->fname2call($filename); 

This method converts the filename representation of a callsign into a 
valid callsign. It addresses the problems that / is a directory splitter 
and therefore reserved in filenames. so this exchanges the - with a /. 

=cut
#------------------------------------------------------------------------------------
# an escaped call for filesystem purposes
sub fname2call {
	my $obj=shift; 
	my $call=shift; 
	if ( ! $call ) { die "we should get a callsign as parameter to this function\n"; } 
	#$call=~s/-/\//g; 
	$call=~s/:/\//g; 
	return $call; 
}

#------------------------------------------------------------------------------------
=pod

=head2 call2fname()

my $filename=$obj->call2fname($call); 

This method converts a callsign into its filename representation. 
It addresses the problems that / is a directory splitter 
and therefore reserved in filenames. so this exchanges the / with a -. 

=cut
#------------------------------------------------------------------------------------
# an escaped call for filesystem purposes
sub call2fname {
	my $obj=shift; 
	my $call=shift; 
	if ( ! $call ) { die "we should get a callsign as parameter to this function\n"; } 
	#$call=~s/\//-/g; 
	$call=~s/\//:/g; 
	return $call; 
}

#------------------------------------------------------------------------------------
=pod

=head2 ensure_path()

$obj->ensure_path($dir); 

Ensures that the path $dir really iss there. If it is not, it creates one, if 
that fails it dies. The path creation is done recursively. The method can be used 
if a code requires to have a directory present, if you want to copy or link a file 
to it for example. 

=cut
#------------------------------------------------------------------------------------
############################################################
# maybe we can borrow this from some sort of helper lib
############################################################
sub ensure_path {
	my $obj=shift; 
	my $path=shift;
	if (( -e $path ) and ( ! -d $path ) and ( ! -l $path ))  {
		die "there is something at this path $path neither directory nor link\n"; 
	}
	if (! -e $path )  {
		# create directory here 
		$obj->ensure_path(dirname($path)); 
		mkdir($path) or die "Can't mkdir $path\n"; 
	}
	# it is ok otherwise
}

#------------------------------------------------------------------------------------
=pod

=head2 scan_dir()

my @basenames=$obj->scan_dir($dir, $regex); 

This the ls of the project. it does an opendir and scans for files matching 
$regex (it is a perl regular expression) the resulting file list, without 
. and .. of course is returned. The returned filenames are basenames without 
path.

=cut
#------------------------------------------------------------------------------------
sub scan_dir {
	my $objSelf=shift;
	my $sDir=shift;
	my $sPrefix=shift; 
	my @aFiles=shift; 

	if ( ! $sDir ) { die "I need a directory to scan\n"; }
	if ( ! $sPrefix ) { die "I need an expression to scan for\n"; }

	if ( ! -e $sDir ) { 
			# the directory does not exist this (and only this) means return
			return(); 
	}

	opendir(DIR, $sDir) or die "directory $sDir to scan is not there\n";

	eval "\@aFiles = grep { /$sPrefix/ } readdir DIR";
		
	closedir DIR;
	
	@aFiles = grep { ! /^(\.|\.\.)$/ } @aFiles;	# filter . and ..

	return (@aFiles);
}

#------------------------------------------------------------------------------------
=pod

=head2 scan_dir_ordered_btime()

my @basenames=$obj->scan_dir_ordered_btime($dir, $regex); 

like scan_dir() but returns a list ordered wich is ordered by 
the user.btime extended attribute of the Filesystem
 
=cut
#------------------------------------------------------------------------------------
sub scan_dir_ordered_btime {
	my $obj=shift;
	my $dir=shift;
	my $prefix=shift; 
	my $by=shift; 
	
	return map {basename($_)} 
		sort(
			map { 
				sprintf(
					"%011d", 
					(getfattr($dir."/".$_, "user.btime") || (stat($dir."/".$_))[9])
				)."/".$_
				 
			} 
			$obj->scan_dir($dir, $prefix)
		); 
}


#------------------------------------------------------------------------------------
=pod

=head2 scan_dir_ordered()

my @basenames=$obj->scan_dir_ordered($dir, $regex); 

like scan_dir() but returns a list ordered by mtime and alphabet if two files 
have the same mtime. 

=cut
#------------------------------------------------------------------------------------
sub scan_dir_ordered {
	my $obj=shift;
	my $dir=shift;
	my $prefix=shift; 

	return map {basename($_)} 
		sort(
			map { sprintf("%011d", (stat($dir."/".$_))[9])."/".$_ } 
				$obj->scan_dir($dir, $prefix)
		); 
}



#------------------------------------------------------------------------------------
=pod

=head2 get_pid()

my $pid=$obj->get_pid($pidfile); 
my $pid=$obj->get_pid(); 

This returns the pid out of a pidfile given either as method parameter or 
through the pidfile option of the object. The PIDfile contains the pid as 
string without any linebreaks.  

=cut
#------------------------------------------------------------------------------------
sub get_pid {
	my $o=shift; 
	my $pfile=$o->{pidfile}; 

	if ( ! -f $pfile ) { return undef; }
	
	my $p; 
	open(PID, "< $pfile") or die "cant open pidfile\n"; 
	while(<PID>) { $p.=$_; }
	close PID ; 
	
	return $p; 
}

#------------------------------------------------------------------------------------
=pod

=head2 wakeup_processor()

$obj->wakeup_processor(); 

sends a kill -HUP to the qtc net processor, causing the processor to stop 
it's sleep and start processing of messages immidiately. $obj->{pidfile} 
must be used for this method. 

=cut
#------------------------------------------------------------------------------------
sub wakeup_processor {
	my $obj=shift;
	eval { 
		if ( -e $obj->{pidfile} ) {
			kill('HUP', $obj->get_pid); 
		}
	};
}


###############################################
# the allowed letters routinges will strip 
# down user data as needed. 
###############################################
#------------------------------------------------------------------------------------
=pod

=head2 allowed_letters_for_telegram()

my $telegram_text=$obj->allowed_letters_for_telegram($text); 

this does a lower case convertion and strips away any character that is not 
allowed for qtc-net telegrams. it also cuts the string down to the allowed 
300 characters for a message. The new telegram text if any is then returned. 

=cut
#------------------------------------------------------------------------------------
sub allowed_letters_for_telegram {
	my $obj=shift; 
	my $telegram=shift; 
	
	$telegram=lc($telegram); 
	$telegram=~s/\t/\ /g;
	# this set of regexes is to convert native language umlaute to something transferable
	# if the length becomes longer than 300 it will stripped later
	# right now only german umlaute are translated that way, but ther can be others. 
	$telegram=~s/ä/ae/g;
	$telegram=~s/ö/oe/g;
	$telegram=~s/ü/ue/g;
	$telegram=~s/ß/sz/g;
	# There should be a working regex to stip any character not allowed from the call 
	# I did not find one... 
	my $t;
	while ($telegram) { 
		my $x=substr($telegram, 0, 1);  $telegram=substr($telegram, 1); 
		if ($x=~/([a-z]|[0-9]|\/|\.|,|\ |\?)/) { $t.=$x; } 
		if ( length($t) >= 300 ) { $telegram=''; }
	} 
	return $t; 
}

#------------------------------------------------------------------------------------
=pod

=head2 allowed_letters_for_call()

 my $callsign_text=$obj->allowed_letters_for_call($text); 

this does a lower case convertion and strips away any character that is not 
allowed for callsigns. The new callsign text if any is then returned. 

=cut
#------------------------------------------------------------------------------------
sub allowed_letters_for_call {
	my $obj=shift; 
	my $call=shift; 
	
	$call=lc($call); 
	# There should be a working regex to stip any character not allowed from the call 
	# I did not find one... 
	my $t; 
	while ($call) { 
		my $x=substr($call, 0, 1);  $call=substr($call, 1); 
		if ($x=~/([a-z]|[0-9]|\/)/) { $t.=$x; } 
	} 
	return $t; 
}

#------------------------------------------------------------------------------------
=pod

=head2 ts_str()

 my $timestamp_string=$obj->ts_str(); 

This method returns an ISO Timestamp as readable text in UTC. 
Mainly for debugging output etc in the processor. 

=cut
#------------------------------------------------------------------------------------
sub ts_str {
	my $o=shift; 
	return strftime("%Y-%m-%d %H:%M:%S UTC", gmtime(time));
}

1; 
=pod

=head1 AUTHOR

Hans Freitag <oe1src@oevsv.at>

=head1 LICENCE

GPL v3

=cut
