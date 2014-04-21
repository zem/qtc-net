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
if ( $type !~ /^new|all|sent$/ ) { die "unknown type"; }

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
    <title>'.$type.' QTC Net Telegrams</title>
    <link>'.$url.'</link>
    <description>New Telegrams channel for '.$url.'</description>
    <language>en-en</language>
    <copyright>GPLV3 qtc-rss.cgi</copyright>
    <pubDate>'.strftime("%y %m %d %H:%M:%S UT", gmtime(time)).'</pubDate>
';
foreach my $call (@calls) {
$callurl=$url."?call=".$q->url_encode($call);

	foreach my $msg ($qry->list_telegrams($call, $type)) {
		print '
    <item>
      <title>'.$q->escapeHTML($msg->telegram).'</title>
      <description>from: '.$q->escapeHTML($msg->from).'  to: '.$q->escapeHTML($call).' '.$q->escapeHTML($msg->to).'</description>
      <link>'.$callurl.'</link>
      <author>'.$q->escapeHTML($msg->call).'@lookslikeanemail</author>
      <guid isPermaLink="false">'.$q->escapeHTML($msg->filename).'</guid>
      <pubDate>'.strftime("%y-%m-%d %H:%M:%S UT", gmtime($msg->telegram_date)).'</pubDate>
    </item>
';

	}
}
print '  </channel>
';

print '</rss>';


