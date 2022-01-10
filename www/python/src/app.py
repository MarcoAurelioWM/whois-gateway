#! /usr/bin/env python
import sys
import six
from ipwhois import IPWhois, WhoisLookupError
import cgitb
import os
import re
from six.moves import urllib
import cgi
import json
import requests
import socket
import geoip2.database
from flask import Flask, request

PROJECT = 'whois-referral'
SITE = '//'+PROJECT+'.toolforge.org'
LOGDIR = '/data/project/'+PROJECT+'/logs'

PROVIDERS = {
    'ARIN': lambda x: 'http://whois.arin.net/rest/ip/' + urllib.parse.quote(x),
    'RIPENCC': lambda x: 'https://apps.db.ripe.net/search/query.html?searchtext=%s#resultsAnchor' % urllib.parse.quote(x),
    'AFRINIC': lambda x: 'http://afrinic.net/cgi-bin/whois?searchtext=' + urllib.parse.quote(x),
    'APNIC': lambda x: 'http://wq.apnic.net/apnic-bin/whois.pl?searchtext=' + urllib.parse.quote(x),
    'LACNIC': lambda x: 'http://lacnic.net/cgi-bin/lacnic/whois?lg=EN&amp;query=' + urllib.parse.quote(x)
}

TOOLS = {
    'Stalktoy': lambda x: 'https://tools.wmflabs.org/meta/stalktoy/' + x,
    'GlobalContribs': lambda x: 'https://tools.wmflabs.org/guc/index.php?user=%s&amp;blocks=true' % x,
    'ProxyChecker': lambda x: 'https://ipcheck.toolforge.org/index.php?ip=%s' % x,
    'Geolocation': lambda x: 'https://whatismyipaddress.com/ip/%s' % x,
    'Bullseye': lambda x: 'https://bullseye.toolforge.org/ip/%s' % x,
}

geolite_file = '/data/project/'+PROJECT+'/GeoLite2-City_20201013/GeoLite2-City.mmdb'
geoip_reader = None
if os.path.exists(geolite_file):
    geoip_reader = geoip2.database.Reader(geolite_file)

ipinfo_file = '/data/project/'+PROJECT+'/ipinfo_token'
ipinfo_token = None
if os.path.exists(ipinfo_file):
    try:
        f = open(ipinfo_file)
        ipinfo_token = f.read().strip()
    except:
        pass


def order_keys(x):
    keys = dict((y, x) for (x, y) in enumerate([
        'geolite2', 'geo_ipinfo',
        'asn_registry', 'asn_country_code', 'asn_cidr', 'query',
        'referral', 'nets', 'asn', 'asn_date',
        'name', 'description', 'address',
        'city', 'state', 'country', 'postal_code',
        'cidr', 'range', 'created', 'updated', 'handle', 'parent_handle',
        'ip_version', 'start_address', 'end_address',
        'abuse_emails', 'tech_emails', 'misc_emails']))
    if x in keys:
        return '0_%04d' % keys[x]
    else:
        return '1_%s' % x


def lookup(ip, rdap=False):
    obj = IPWhois(ip)
    if rdap:
        return obj.lookup_rdap(asn_methods=['dns', 'whois', 'http'])
    else:
        try:
            field_list = ['name', 'cidr', 'handle', 'description', 'country', 'state', 'city', 'address', 'postal_code', 'emails', 'created', 'updated']
            ret = obj.lookup_whois(get_referral=True, get_recursive=False, asn_methods=['dns', 'whois', 'http'], field_list=field_list)
        except WhoisLookupError:
            ret = obj.lookup_whois(asn_methods=['dns', 'whois', 'http'])
        # remove some fields that clutter
        for x in ['raw', 'raw_referral']:
            ret.pop(x, None)
        return ret


def format_new_lines(s):
    return s.replace('\n', '<br/>')


def format_table(dct, target):
    if isinstance(dct, six.string_types):
        return format_new_lines(dct)
    if isinstance(dct, list):
        return '\n'.join(format_table(x, target) for x in dct)
    ret = '<div class="table-responsive"><table class="table table-condensed"><tbody>'
    for (k, v) in sorted(dct.items(), key=lambda x: order_keys(x[0])):
        if v is None or len(v) == 0 or v == 'NA' or v == 'None':
            if k in ('referral',):
                continue
            ret += '<tr class="text-muted"><th>%s</th><td>%s</td></tr>' % (k, v)
        elif isinstance(v, six.string_types):
            if k == 'asn_registry' and v.upper() in PROVIDERS:
                ret += '<tr><th>%s</th><td><a href="%s"><span class="glyphicon glyphicon-link"></span>%s</a></td></tr>' % (
                    k, PROVIDERS[v.upper()](target), v.upper()
                )
            elif k == 'asn':
                ret += '<tr><th>%s</th><td><a href="https://tools.wmflabs.org/isprangefinder/hint.php?type=asn&range=%s">%s</a></td></tr>' % (
                    k, v, v
                )
            else:
                ret += '<tr><th>%s</th><td>%s</td></tr>' % (
                    k, format_new_lines(v)
                )
        else:
            ret += '<tr><th>%s</th><td>%s</td></tr>' % (k, format_table(v, target))
    ret += '</tbody></table></div>'
    return ret


def format_result(result, target):
    return '<div class="panel panel-default">%s</div>' % format_table(result, target)


def format_link_list(header, ls):
    ret = '''
<div class="panel panel-default">
<div class="panel-heading">%s</div>
<div class="list-group">
''' % header

    for (link, title, anchor, cls) in ls:
        ret += '<a class="%s" href="%s" title="%s">%s</a>\n' % (
            ' '.join(cls+['list-group-item']),
            link, title, anchor
        )
    ret += '</div></div>'
    return ret


def format_page():
    ip = request.args.get('ip', '')
    fmt = request.args.get('format', 'html').lower()
    do_lookup = request.args.get('lookup', 'false').lower() != 'false'
    use_rdap = request.args.get('rdap', 'false').lower() != 'false'
    css = '''
.el { display: flex; flex-direction: row; align-items: baseline; }
.el-ip { flex: 0?; max-width: 70%%; overflow: hidden; text-overflow: ellipsis; padding-right: .2em; }
.el-prov { flex: 1 8em; }
th { font-size: small; }
.link-result { -moz-user-select: all; -webkit-user-select: all; -ms-user-select: all; user-select: all; }
'''

    # remove spaces, the zero-width space and left-to-right mark
    if six.PY2:
        ip = ip.decode('utf-8')
    ip = re.sub('[^0-9a-f.:/]', '', ip, flags=re.I)
    ip = ip.strip().strip(u' \u200b\u200e')
    ip_arg = ip
    if '/' in ip:
      ip = ip.split('/')[0]
      cidr = True
    else:
      cidr = False

    result = {}
    error = False
    if do_lookup:
        try:
            result = lookup(ip, use_rdap)
        except Exception as e:
            result = {'error': repr(e)}
            error = True

        geoip_res = geoip_reader.city(ip)
        if geoip_res:
            try:
                result['geolite2'] = geoip_res.country.name
                if geoip_res.subdivisions.most_specific.name:
                    result['geolite2'] = geoip_res.subdivisions.most_specific.name + ", " + result['geolite2']
                if geoip_res.city.name:
                    result['geolite2'] = geoip_res.city.name + ", " + result['geolite2']
            except Exception as e:
                result['geolite2'] = "Unavailable: " + repr(e)

        if ipinfo_token:
            ipinfo = requests.get('https://ipinfo.io/'+ip+'/json?token='+ipinfo_token)
            ipinfo_json = ipinfo.json()
            if ipinfo_json and 'error' not in ipinfo_json:
                result['geo_ipinfo'] = ipinfo_json['country']
                if 'region' in ipinfo_json:
                    result['geo_ipinfo'] = ipinfo_json['region'] + ", " + result['geo_ipinfo']
                if 'city' in ipinfo_json:
                    result['geo_ipinfo'] = ipinfo_json['city'] + ", " + result['geo_ipinfo']


    if fmt == 'json' and do_lookup:
        return '{}\n'.format(json.dumps(result))
        
    ret = '''<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<link rel="stylesheet" href="//tools-static.wmflabs.org/cdnjs/ajax/libs/twitter-bootstrap/3.2.0/css/bootstrap.min.css">
<link rel="stylesheet" href="//tools-static.wmflabs.org/cdnjs/ajax/libs/twitter-bootstrap/3.2.0/css/bootstrap-theme.min.css">
<title>Whois Gateway Beta</title>
<style type="text/css">
{css}
</style>
</head>
<body>
<div class="container">
<div class="row">
<div class="col-sm-5">
<header><h1>Whois Gateway<span style="color: #20c997; font-size: 18px; font-weight: bold; position: relative; text-transform: uppercase; top: -3px; vertical-align: top;">BETA</span></h1></header>
</div>
<div class="col-sm-7"><div class="alert alert-success" role="alert">
<strong>This is a beta version of the Whois Gateway operated by <a href="https://en.wikipedia.org/wiki/User:ST47">ST47</a>.</strong> It adds support for querying referral DNS servers, such as those provided by Cogent for their 38.0.0.0/8 range. This is done automatically when the provider supports it. The source code for this fork is maintained at <a href="https://github.com/wiki-ST47/whois-gateway/">GitHub</a>.
</div></div>
</div>

<div class="row">
<div class="col-sm-9">

<form action="{site}/gateway.py" role="form">
<input type="hidden" name="lookup" value="true"/>
<div class="row form-group {error}">
<div class="col-md-10"><div class="input-group">
<label class="input-group-addon" for="ipaddress-input">IP address</label>
<input type="text" name="ip" value="{ip}" id="ipaddress-input" class="form-control" {af}/>
</div></div>
<div class="col-md-2"><input type="submit" value="Lookup" class="btn btn-default btn-block"/></div>
</div>
</form>
'''.format(site=SITE,
           css=css,
           ip=ip_arg,
           error= 'has-error' if error else '',
           af= 'autofocus onFocus="this.select();"' if (not do_lookup or error) else '')

    if cidr:
      ret += '''<div class="alert alert-warning" role="alert">
The IP address you provided included a CIDR range. The results below apply to the IP address you provided, with the CIDR range ignored. There may be other addresses in that range that are not included in this report.
</div>'''

    if do_lookup:
        link = 'https://%s.toolforge.org/gateway.py?lookup=true&ip=%s' % (PROJECT, ip)
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except IOError:
            pass
        ret += '''
<div class="panel panel-default"><div class="panel-heading">{hostname}</div>
<div class="panel-body">{table}</div></div>

<div class="row form-group">
<div class="col-md-12"><div class="input-group">
<label class="input-group-addon"><a href="{link}">Link this result</a></label>
<output class="form-control link-result">{link}</output>
</div></div>
</div>
'''.format(hostname='<strong>%s</strong>' % hostname if hostname else '<em>(No corresponding host name retrieved)</em>',
           table=format_table(result, ip),
           link=link)

    ret += '''</div>
<div class="col-sm-3">
'''
    ret += format_link_list(
        'Other tools',
        [(q(ip),
          'Look up %s at %s' % (ip, name),
          '<small class="el-ip">%s</small><span class="el-prov"> @%s</span>' % (ip, name),
          ['el'])
         for (name, q) in sorted(TOOLS.items())]
    )

    ret += format_link_list(
        'Sources',
        [(q(ip),
          'Look up %s at %s' % (ip, name),
          '<small class="el-ip">%s</small><span class="el-prov"> @%s</span>' % (ip, name),
          ['el', 'active'] if result.get('asn_registry', '').upper() == name else ['el'])
         for (name, q) in sorted(PROVIDERS.items())]
    )

    ret += '''
</div>
</div>

<footer><div class="container">
<hr>
<p class="text-center text-muted">
<a href="{site}">Whois Gateway</a>
<small>(<a href="https://github.com/wiki-ST47/whois-gateway">source code</a>,
        <a href="https://github.com/whym/whois-gateway">upstream</a>,
        <a href="https://github.com/whym/whois-gateway#api">API</a>)</small>
        on <a href="https://toolforge.org">Toolforge</a> /
<a href="https://github.com/wiki-ST47/whois-gateway/issues">Issues?</a>
</p>
</div></footer>
</div>
</body></html>'''.format(site=SITE)

    return ret

app = Flask(__name__)
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def main_route(path):
    return format_page()

