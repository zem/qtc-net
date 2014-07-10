#!/usr/bin/perl
use qtc::query; 
use CGI::Simple; 
use POSIX qw(strftime); 
use Digest::SHA qw(sha256_hex); 

my $q = CGI::Simple->new;
my @calls=$q->param("call"); 
#@calls=("oe1gsu", "dm3da", "oe1src"); 

my $type=$q->param("type"); 
if ( ! $type ) { $type="timeline"; }
if ( $type !~ /^new|all|sent|timeline|timeline_new$/ ) { die "unknown type"; }

my $dateformat="%a, %d %b %Y %T +0000";
#my $dateformat="%Y-%m-%d %H:%M:%S UTC";

my $anz=$q->param("anz"); 
if (! $anz) { $anz=10; }
if ( $anz !~ /^\d+$/ ) { $anz=10; }

# return file 
print $q->header(
#	-type=>'application/rss+xml',
);

my $url=$ENV{QTC_WEB_URL};
if ( ! $url ) { $url.="https://www.qtc-net.org/qtc-web.cgi"; }

my $path=$ENV{QTC_ROOT};
if ( ! $path ) { $path=$ENV{HOME}."/.qtc"; }

$qry=qtc::query->new(
	path=>$path,
);

####################################################################################
sub telegram_item {
	my $msg=shift; 
	if ( $msg->type ne "telegram" ) { return; }
	my $fromcall=$qry->allowed_letters_for_call($msg->from); 
	my $tocall=$qry->allowed_letters_for_call($msg->to); 
	my $fromcallurl=$url."?call=".$q->url_encode($fromcall)."&type=".$type;
	my $tocallurl=$url."?call=".$q->url_encode($tocall)."&type=".$type;
	
	print '
    <tr>
		<td><b>from:</b></td><td><a href="'.$fromcallurl.'" target="_top">'.$q->escapeHTML($msg->from).'</td>
	 </tr><tr>
		<td><b>to:</b></td><td><a href="'.$tocallurl.'" target="_top">'.$q->escapeHTML($msg->to).'</a></td>
	 </tr><tr>
		<td colspan="2">'.$q->escapeHTML($msg->telegram).'<br/><br/></td>
	</tr>
';
}
#########################################################################################


print '<!DOCTYPE html
	PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
	 "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en-US" xml:lang="en-US">
<head>
<title>ALPHA QTC Network Web Access ALPHA</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
</head>
<body>
<small>
<table width="100%">
';


if ( $#calls == -1 ) { 
	foreach my $msg ($qry->latest_changes(10)) { 
		telegram_item($msg); 
	} 
} else {
	foreach my $call (@calls) {
	$call=$qry->allowed_letters_for_call($call); 
	$callurl=$url."?call=".$q->url_encode($call);
	
		foreach my $msg ($qry->list_telegrams($call, $type, $anz)) {
			telegram_item($msg); 
		}
	}
}

$q->param("anz", $anz+10); 
print '</table>
<center><a href="'.$q->url(-full=>1, -query=>1).'">...</a></center>
</small></body></html>';

