# Parsing and Manipulation Library for Content Security Policy

This is a Python library to parse, manipulate, compare, and generate policies according to the most important features of the [version 1.1 draft of Content Security Policy as of 11 February 2014](http://www.w3.org/TR/2014/WD-CSP11-20140211/). It is mostly useful to analyse violation reports submitted by browsers using CSP's `report-uri` feature.


## Overview of the library

The library contains higher-level objects that represent CSP's main concepts: `URI` represents URIs of various types, including regular http(s) URLs, and a few special URIs with schemes such as `data`, `about` and `chrome-extension`, for instance. `SourceExpression` and its subclasses indicate sources from which resources may be loaded. `Directive` contains a set of whitelisted source expressions for a specific resource type, such as all locations from which images may be loaded. `Policy` is a set of directives, at most one for each resource type, and specifies for a protected document the locations from which included resources of certain types may be loaded. `Report` corresponds to violation reports that browsers can send back to a web site under CSP's `report-uri` feature when a policy is violated. It contains various fields that specify the details of the violation, such as the policy of the site, the violated directive, and the URI of the resource that violated the policy. Additionally, `LogEntry` is a data type that we added to represent additional information about a report received at a web site, such as the timestamp and the IP address and user agent string of the browser that sent the report.

All data types are immutable. They implement the standard hash and equality methods so that they can be used intuitively in Python's data structures such as lists and sets. For instance, two lists containing the same policies (even if they are not the same `Policy` instance) will compare as equal. The `repr(.)` and `str(.)` methods will convert the objects into the string representation used in the CSP standard. Each data type also has an associated parser to read from strings. Instead of returning `None` or throwing an exception, most methods will instead return a special singleton instance `INVALID` in case of errors.


## Collecting violation reports

The file `src/examples/csp.cgi` contains a sample CGI script that can receive CSP violation reports from browsers and store them into files.

We recommend to send the following CSP headers to browsers:

    Content-Security-Policy-Report-Only: default-src 'none'; script-src 'unsafe-eval' 'unsafe-inline'; object-src 'none'; style-src 'unsafe-inline'; img-src 'none'; media-src 'none'; frame-src 'none'; font-src 'none'; connect-src 'none'; report-uri http://example.com/csp.cgi?type=regular
    Content-Security-Policy-Report-Only: default-src *; script-src * 'unsafe-inline'; style-src * 'unsafe-inline'; report-uri http://example.com/csp.cgi?type=eval
    Content-Security-Policy-Report-Only: default-src *; script-src * 'unsafe-eval'; style-src *; report-uri http://example.com/csp.cgi?type=inline

They operate in report-only mode, that is, the policy is only simulated, not enforced, and will not cause the web site to malfunction. The three headers should all be sent simultaneously. They are necessary to capture different types of violations (violation reports as currently sent by browsers cannot distinguish `inline` from `eval`-type violations).


## Example: Generate a policy

The following sample code generates a policy that whitelists every resource that caused a violation report in `inputfile`, assuming that the reports were collected with a methodology similar to the one outlined above:

```python
from csp.tools.fileio import LogEntryDataReader
from csp.policy import Policy

inputfile = "tests/csp/data/sample-logentries.dat"
fin = LogEntryDataReader(True)
fullPolicy = None

def handleEntry(entry):
    global fullPolicy
       
    newPolicy = entry.generatePolicy()
    if newPolicy is Policy.INVALID():
        print "generated invalid policy from log entry '%s'" % str(entry)
        return
        
    if fullPolicy is None:
        fullPolicy = newPolicy
    else:
        fullPolicy = fullPolicy.combinedPolicy(newPolicy)

fin.load(inputfile, handleEntry)

print "Generated policy with full paths: %s" % str(fullPolicy)
print ""
print "Generated policy without paths: %s" % str(fullPolicy.withoutPaths())
```

In practice, additional steps are necessary to filter the reports before a policy is derived. Furthermore, the resulting policy needs to be processed manually in order to remove any directives that might be due to attacks or undesirable resources injected into the web site. The directive `default-src 'none'` should be added to the policy so that resources not explicitly allowed will be forbidden (the default behaviour of CSP is to assume `default-src *` when there is no `default-src` directive specified in the policy).


## External dependencies

This library has no external dependencies. To run the tests, however, you'll need `pytest`.

    py.test src/tests/


## Known issues

1. When generating a policy from violation reports as in the example above, it is possible that the resulting policy cannot be parsed by this library when it uses a scheme that is not listed in `defaults.supportedSchemes` or `defaults.schemePortMappings`. The workaround is to add the unknown scheme to these data structures.

2. Some script-related reports include the value `blob` for the field `blocked-uri`. This library incorrectly parses this value as the host name of an URI.

## Concluding remarks

If you find this library useful, we'd love to hear from you: [Northeastern University Systems Security Lab](http://seclab.ccs.neu.edu/) / [Tobias Lauinger](http://tobias.lauinger.name/).
