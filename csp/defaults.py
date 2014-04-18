'''
This file contains default settings for optional parameters in the CSP package (such as
mappings from scheme names to the associated default port number). These settings should
NOT be modified at runtime. If you need to programmatically change some of the values,
change them during object creation (they are configurable).

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''


# URI

schemesWithNoDoubleSlash = ("data", "about", "view-source")
defaultURIScheme = 'http'
defaultURIPort = 80
schemePortMappings = {'http': 80, 'https': 443, 'data': None, 'chrome-extension': None, 
                                     'safari-extension': None, 'chromenull': None, 'chromeinvoke': None,
                                     'chromeinvokeimmediate': None, 'mx': None, 'moz-icon': None,
                                     'about': None, 'view-source': None, 'se-extension': None,
                                     'ws': None}
portSchemeMappings = {80: 'http', 443: 'https', 8080: 'http'}


# SourceExpression

supportedSchemes = schemePortMappings.keys()


# Directive

directiveTypeTranslations = {"xhr-src": "connect-src"}
allowedDirectiveTypes = ("base-uri", "child-src", "connect-src", "default-src",
                               "font-src", "form-action", "frame-ancestors", "frame-src",
                               "img-src", "media-src", "object-src", "script-src", "style-src")
schemeOnly = ("data", "chrome-extension", "safari-extension", "chromenull", "chromeinvoke", "chromeinvokeimmediate",
              "mx", "moz-icon", "about", "view-source")

# Policy

ignoredDirectiveTypes = ("plugin-types", "referrer", "reflected-xss", "report-uri", "sandbox")
defaultSrcReplacementDirectiveTypes = ("child-src", "connect-src", "font-src", "img-src", "media-src",
                                  "object-src", "script-src", "style-src")


# Report

uriKeys = ('blocked-uri', 'document-uri', 'referrer') # source-file excluded because some parsing issues
directiveKeys = ('violated-directive',)
policyKeys = ("original-policy",)
reportKeyNameReplacements = {'document-url': 'document-uri'}
requiredReportKeys = ('blocked-uri', 'violated-directive', 'document-uri')