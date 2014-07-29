#!/usr/bin/perl
use qtc::query; 
use CGI::Simple; 
use POSIX qw(strftime); 
use Digest::SHA qw(sha256_hex); 

my $q = CGI::Simple->new;
my @calls=$q->param("call"); 
#@calls=("oe1gsu", "dm3da", "oe1src"); 

my $type=$q->param("type"); 
if ( ! $type ) { $type="new"; }
if ( $type !~ /^new|all|sent|timeline|timeline_new$/ ) { die "unknown type"; }

my $type=$q->param("type"); 
if ( ! $type ) { $type="timeline"; }
if ( $type !~ /^new|all|sent|timeline|timeline_new$/ ) { die "unknown type"; }

my $anz=$q->param("anz"); if ( ! $anz ) { $anz=40; } 
my $offset=$q->param("offset"); if ( ! $offset ) { $offset=0; } 

my $dateformat="%a, %d %b %Y %T +0000";
#my $dateformat="%Y-%m-%d %H:%M:%S UTC";

# return file 
print $q->header(
	-type=>'application/rss+xml',
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
	my $call=shift; 
	if ( $msg->type ne "telegram" ) { return; }
	if ( $type =~ /^timeline/ ) { 
		if ( ! $call ) { return; }  # if there is a timeline there is a call
	} else {
		$call=$qry->allowed_letters_for_call($msg->to); 
	}
	my $callurl=$q->escapeHTML($url."?call=".$q->url_encode($call).'&type='.$type.'#'.$msg->filename);

	my $de=$msg->to." de ".$msg->from." = "; 
	if ( $#calls != -1 ) { 
		if ( $msg->from eq $msg->to ) { 
			$de="de ".$msg->from." = ";
		} else {
			my $op=$qry->operator($msg->to); 
			if ( $op ) { 
				foreach my $alias ($op->set_of_aliases) {
					if ( $alias eq $msg->from ) {
						$de="de ".$msg->from." = ";
						break; 
					}
				}
			}
		}
	}
	
	print '
    <item>
      <title>'.$q->escapeHTML($de.$msg->telegram).'</title>
      <description>'.$q->escapeHTML($to).' de '.$q->escapeHTML($msg->from).'</description>
      <link>'.$callurl.'</link>
      <author>'.$q->escapeHTML($msg->call).' ('.$q->escapeHTML($msg->call).')</author>
      <guid isPermaLink="false">'.$q->escapeHTML($msg->filename).'</guid>
      <pubDate>'.strftime($dateformat, gmtime($msg->telegram_date)).'</pubDate>
    </item>
';
}
#########################################################################################


print '<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
';

print'  <channel>
    <title>'.$type.' QTC Net Telegrams</title>
    <link>'.$url.'</link>
    <description>New Telegrams channel for '.$url.'</description>
    <language>en-en</language>
    <copyright>GPLV3 qtc-rss.cgi</copyright>
    <pubDate>'.strftime($dateformat, gmtime(time)).'</pubDate>
';
print '<atom:link href="'.$q->escapeHTML($q->url(-full=>1, -query=>1)).'" rel="self" type="application/rss+xml" />';

if ( $#calls == -1 ) { 
	foreach my $msg ($qry->latest_changes(40)) { 
		telegram_item($msg); 
	} 
} else {
	foreach my $call (@calls) {
	$call=$qry->allowed_letters_for_call($call); 
	$callurl=$url."?call=".$q->url_encode($call);
	
		foreach my $msg ($qry->list_telegrams($call, $type, $anz, $offset)) {
			telegram_item($msg, $call); 
		}
	}
}

print '  </channel>
';

print '</rss>';


