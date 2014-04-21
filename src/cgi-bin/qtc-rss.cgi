#!/usr/bin/perl
use qtc::query; 
use qtc::misc; 
use qtc::msg; 
use CGI::Simple; 
use File::Basename; 
use POSIX qw(strftime); 

my $q = CGI::Simple->new;
my @calls=$q->param("call"); 
#@calls=("oe1gsu", "dm3da", "oe1src"); 

# return file 
print $q->header(
	-type=>'application/x-rss+xml',
);

my $url=$ENV{QTC_WEB_URL};
if ( ! $url ) { $url.="https://www.qtc-net.org/qtc-web.cgi"; }

my $path=$ENV{QTC_ROOT};
if ( ! $path ) { $path=$ENV{HOME}."/.qtc"; }

$qry=qtc::query->new(
	path=>$path,
);

print '<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
';



print'  <channel>
    <title>QTC Net Telegrams</title>
    <link>'.$url.'</link>
    <description>New Telegrams channel for '.$url.'</description>
    <language>en-en</language>
    <copyright>GPLV3 qtc-rss.cgi</copyright>
    <pubDate>'.strftime("%Y-%m-%d %H:%M:%S UTC", gmtime(time)).'</pubDate>
';
foreach my $call (@calls) {
$callurl=$url."?call=".$q->url_encode($call);

	foreach my $msg ($qry->list_telegrams($call, "new")) {
		print '
    <item>
      <title>'.$q->escapeHTML($msg->telegram).'</title>
      <description>from: '.$q->escapeHTML($msg->from).'  to: '.$q->escapeHTML($call).' '.$q->escapeHTML($msg->to).'</description>
      <link>'.$callurl.'</link>
      <author>'.$q->escapeHTML($msg->call).'</author>
      <guid>'.$q->escapeHTML($msg->filename).'</guid>
      <pubDate>'.strftime("%Y-%m-%d %H:%M:%S UTC", gmtime($msg->telegram_date)).'</pubDate>
    </item>
';

	}
}
print '  </channel>
';

print '</rss>';


