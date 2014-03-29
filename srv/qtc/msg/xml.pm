package qtc::msg::xml; 
#use POSIX qw(strftime);
use Digest::SHA qw(sha256_hex);
use XML::XPath; 
use qtc::signature; 
use File::Basename; 
use MIME::Base64; 
use qtc::msg;
use qtc::misc;
@ISA=("qtc::msg", "qtc::misc"); 


################################################################
# The data that is going to be signed is represented as XML 
# parseable but without namespacing, pi, header and spaces 
# between the elements  even if there may some other 
# message formats available, signatures should always be done 
# in this format.  
################################################################
sub signed_content_xml {
	# TO be implementes
	my $obj=shift; 
	$obj->is_object_valid;
	
	my $ret="<".$obj->{type}.">";
	foreach my $field (sort keys %{$msg_types{$obj->{type}}}) {
		if ( ref($msg_types{$obj->{type}}->{$field}) eq "ARRAY" ) { 
			foreach my $dat (@{$obj->{$field}}) {
				$ret.="<$field>".$dat."</$field>"; 
			}
		} else {
			$ret.="<$field>".$obj->{$field}."</$field>"; 
		}
	}
	$ret.="</".$obj->{type}.">";
}

sub as_xml {
	# TO be implementes
	my $obj=shift; 
	$obj->is_object_valid;
	
	my $ret="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
	$ret.="<qtc>\n"; 
	$ret.="<version>".$obj->version."</version>\n";	
	#$ret.="<rcvd_date>".$obj->rcvd_date."</rcvd_date>\n";	
	$ret.="<call>".$obj->call."</call>\n";	
	$ret.="<type>".$obj->type."</type>\n";	
	$ret.="<signature>".$obj->signature."</signature>\n";	
	$ret.="<signature_key_id>".$obj->signature_key_id."</signature_key_id>\n";	
	$ret.="<checksum>".$obj->checksum."</checksum>\n";	
	$ret.=$obj->signed_content_xml."\n"; 
	$ret.="</qtc>\n"; 

	return $ret; 
}

sub xml_filename {
	my $obj=shift;
	$obj->is_object_valid;
	
	my $filename=$obj->type."_".$obj->escaped_call."_".$obj->checksum.".xml";

	if ( ! $obj->{filename} ) { 
		$obj->{filename}=$filename; 
	} else {
		if ( $obj->{filename} ne $filename ) { 
			die "somehow the object filename $obj->{filename} does not match with the generated $filename\n"; 
		}
	}
	return $filename; 
}

sub xml_to_filesystem {
	my $obj=shift; 
	my $path=shift; 
	$obj->is_object_valid;
	my $filename=$obj->filename;
	$obj->{path}=$path; 
	
	open(WRITE, "> ".$path."/.".$filename.".tmp") or die "cant open $path/$filename\n"; 
	print WRITE $obj->as_xml or die "Can't write data to disk\n"; 
	close(WRITE); 
	link($path."/.".$filename.".tmp", $path."/".$filename) or die "Can't link to path\n"; 
	unlink($path."/.".$filename.".tmp") or die "Can't unlink tmpfile, this should never happen\n"; 
}


sub xml_link_to_path {
	my $obj=shift;
	if ( ! $obj->{path} ) { die "please store object first\n"; }
	foreach my $path (@_) {
		$obj->ensure_path($path); 
		if ( ! -e $path."/".$obj->xml_filename ) {
			link($obj->{path}."/".$obj->filename, $path."/".$obj->xml_filename) or die "I cant link this file to $path\n"; 
		}
	}
}

sub xml_unlink_at_path {
	my $obj=shift;
	foreach my $path (@_) {
		$obj->ensure_path($path); 
		if ( -e $path."/".$obj->xml_filename ) {
			unlink($path."/".$obj->xml_filename) or die "I cant unlink this file to $path\n"; 
		}
	}
}

# load data from string or filesystem 
sub load_xml_file {
	my $obj=shift; 
	my $path=shift; 
	my $filename=shift; 
	if ( ! $path ) { die "I need a path to load a message\n"; }
	if ( ! -e $path ) { die "Path $path does not exist\n"; } 
	$obj->{path}=$path; 
	if ( ! $filename ) { die "I need a filename\n"; } 
	my $xml; 	

	open(READ, "< $path/$filename") or die "cant open $filename\n"; 
	while(<READ>) { $xml.=$_; }
	close(READ); 

	$obj->load_xml($xml); 
}

# load data from string or filesystem 
sub load_xml {
	my $obj=shift; 
	my $xml=shift; 
	#print $xml; 
	if ( ! $xml ) { die "I need some xml data \n"; } 
	my $xp=XML::XPath->new(xml=>$xml) or die "can't create XPath object from message\n"; 
	# let us store the common values
	$obj->call($xp->getNodeText("qtc/call")->value());
	$obj->type($xp->getNodeText("qtc/type")->value());
	# we will copy every field then 
	foreach my $field (sort keys %{$msg_types{$obj->type}}) {
		if ( ref($msg_types{$obj->{type}}->{$field}) eq "ARRAY" ) {
			my @nodes=$xp->findnodes("qtc/".$obj->type."/".$field);
			foreach my $node (@nodes) {
				push @{$obj->{$field}}, $node->string_value; 
			}
		} else {
			$obj->{$field}=$xp->getNodeText("qtc/".$obj->type."/".$field)->value();
		}
	}
	# as well as checksum and signature 
	$obj->checksum($xp->getNodeText("qtc/checksum")->value());
	$obj->signature($xp->getNodeText("qtc/signature")->value(), $xp->getNodeText("qtc/signature_key_id")->value());
	# if we are not dead yet, well done 
}

1; 
