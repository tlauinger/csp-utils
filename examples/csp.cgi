#!/usr/bin/python
'''
Example CGI script that collects incoming CSP violation reports and stores them in files.
Assumes that the following CSP headers are sent by the server:

Content-Security-Policy-Report-Only: default-src 'none'; script-src 'unsafe-eval' 'unsafe-inline'; object-src 'none'; style-src 'unsafe-inline'; img-src 'none'; media-src 'none'; frame-src 'none'; font-src 'none'; connect-src 'none'; report-uri http://example.com/csp.cgi?type=regular
Content-Security-Policy-Report-Only: default-src *; script-src * 'unsafe-inline'; style-src * 'unsafe-inline'; report-uri http://example.com/csp.cgi?type=eval
Content-Security-Policy-Report-Only: default-src *; script-src * 'unsafe-eval'; style-src *; report-uri http://example.com/csp.cgi?type=inline

All three headers should be sent for each protected document. They are using CSP's report-only
mode, that is, browsers will not enforce the policies but only simulate them.  Web browsers
will send a report of each (simulated) violation of the policy to the address of this CGI script
(customise the URL in the three headers). Note that Firefox sends reports only when the sink
for the reports is on the same domain as the protected document (or on a subdomain).

The first header collects reports for violations concerning regular resources located in files.
The second header collects reports for calls to eval(.) and similar JavaScript functions.
The third header collects reports for violations due to script or style definitions inlined in
the document. 

A typical way to deploy a CSP report sink would be to add the three headers to each page on a
web site. For Apache httpd, an example .htaccess file sending the headers for all .html files
could look like this:

<FilesMatch "\.html$">
	Header set Content-Security-Policy-Report-Only "default-src 'none'; ... report-uri /csp.cgi?type=regular"
	Header add Content-Security-Policy-Report-Only "default-src *; ... report-uri /csp.cgi?type=eval"
	Header add Content-Security-Policy-Report-Only "default-src *; ... report-uri /csp.cgi?type=inline"
</FilesMatch>

When a report is received, information such as the timestamp, IP address and user agent string
of the browser sending the report will be added and the resulting log entry will be stored in
a new file in the specified directory. File names include the timestamp in order to be unique.
Example: reports_2013-12-14_025835.280001.log

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''


import sys
import os
import datetime
import json


# CONFIGURE THIS: The directory where reports will be stored. Must be writeable for the CGI process.
outputpath = "../offline/csp/"


print "Content-Type: text/plain"
print ""

report = sys.stdin.read()
try:
    cspreport = json.loads(report)
except Exception:
    cspreport = None
if cspreport is None or not "csp-report" in cspreport:
    print "Thanks anyway."
    sys.exit()
print "Thanks for the report."

uri = os.environ.get("REQUEST_URI", "")
if "type=eval" in uri:
    policyType = "eval"
elif "type=inline" in uri:
    policyType = "inline"
else:
    policyType = "regular"
cspreport['policy-type'] = policyType

now = datetime.datetime.utcnow()
timestamp_json = now.strftime("%Y-%m-%d %H:%M:%S.%f")
cspreport['timestamp-utc'] = timestamp_json

cspreport['remote-addr'] = os.environ.get("REMOTE_ADDR", "")
cspreport['http-user-agent'] = os.environ.get("HTTP_USER_AGENT", "")

timestamp_filename = now.strftime("%Y-%m-%d_%H%M%S.%f")
with open("%s/reports_%s.log" % (outputpath, timestamp_filename), "w") as f:
    f.write(json.dumps(cspreport))
