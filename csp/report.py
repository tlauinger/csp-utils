'''
Represents a browser-submitted report of a violation of a CSP policy. The
format of these reports is described in detail in the CSP 1.1 draft 
http://www.w3.org/TR/2014/WD-CSP11-20140211/#reporting Additionally, the
default settings convert the field names used in earlier CSP implementations
to the current format (e.g., replace 'document-url' with 'document-uri').

These are the most interesting fields contained in most reports:
    'violated-directive': the Directive of the policy that was violated.
    'blocked-uri': the URI of the resource that violated the policy, or
                    the empty string for eval/inline violations (depending
                    on the browser).
    'document-uri': the (host) document in which the violation occurred.
    'original-policy': the full Policy that was violated.
    'source-file': set to the URI of a file if the violation occurred not
                    inside the host document, but a document included
                    by the host document (such as an external script).
                    
Reports are an enhanced version of a Python dictionary that contains
URI, Directive and Policy objects instead of basic data types for some
of the entries above (depending on the configuration). ReportParser can
parse violation reports from JSON dictionary strings (as collected from
browsers) or from a Python dictionary with primitive type values.

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''

import collections
import json
from directive import DirectiveParser, Directive
from policy import PolicyParser, Policy
from uri import URIParser, URI
from reportjsonencoder import ReportJSONEncoder
import defaults

class Report(collections.Mapping):
    """
    A CSP violation report, internally implemented similar to a dictionary, with certain keys returning objects
    instead of strings (such as 'original-policy', 'violated-directive').
    Immutable.
    """
    
    _invalid = None
    
    def __init__(self, dataDict):
        """
        Generates a new CSP violation report from the given data.
        
        'dataDict' is a dictionary with the field names of a CSP violation report as keys. The corresponding values
        can be either original or an higher-abstraction object (such as URI, Directive, Policy) and MUST all be
        immutable.
        """
        self._hash = None
        self._str = None
        self._repData = dict(dataDict)
        
    @staticmethod
    def INVALID():
        """
        Special static singleton Report representing an invalid report (could not be parsed).
        """
        if Report._invalid is None:
            Report._invalid = Report({})
        return Report._invalid
    
    def generatePolicy(self, reportType):
        """
        Generates a new basic policy that allows exactly the kind of event that caused this CSP violation report,
        assuming the given 'reportType' (permitted values are 'regular', 'eval', and 'inline').
        This assumes that this report contains a specific violated-directive field (it may not be 'default-src').
        If any inconsistent reports are used to generate policies, the policies themselves will be inconsistent. 
        
        Policies should be collected with CSP headers like these:
        
        Content-Security-Policy-Report-Only: default-src 'none'; script-src 'unsafe-eval' 'unsafe-inline'; object-src 'none'; style-src 'unsafe-inline'; img-src 'none'; media-src 'none'; frame-src 'none'; font-src 'none'; connect-src 'none'; report-uri /csp.cgi?type=regular
        Content-Security-Policy-Report-Only: default-src *; script-src * 'unsafe-inline'; style-src * 'unsafe-inline'; report-uri /csp.cgi?type=eval
        Content-Security-Policy-Report-Only: default-src *; script-src * 'unsafe-eval'; style-src *; report-uri /csp.cgi?type=inline
        
        The "type" parameter in the report-uri is equivalent to the 'reportType' parameter of this method.
        
        The results should also be filtered to ensure that only reports sent by fully compatible browsers
        are taken into account. This implementation does not handle URIs in any special way. That is, it does
        not add or remove ports, path/query components, or replace them with the 'self' keyword.
        
        The result is a basic Policy containing one whitelisted resource (corresponding to the violated directive). 
        In practice, it should not be used alone, but be combined with basic policies generated for other violations
        on the same web site. It should also be prepended with "default-src 'none'" to ensure that only the
        whitelisted resources are allowed. (The standard behaviour of CSP in absence of any default Directive is
        to assume "default-src *", which may not be the desired behaviour.)
        
        The result is Policy.INVALID() if (1) the violated directive is missing, Directive.INVALID() or 'default-src', 
        or a special type incompatible with 'reportType', (2) if 'reportType' is none out of 'regular', 'inline' or 'eval', 
        (3) the 'blocked-uri' is URI.INVALID() or not a regular URI in the 'reportType'=='regular' case.
        """
        if (self == Report.INVALID()
            or 'violated-directive' not in self
            or 'blocked-uri' not in self):
            return Policy.INVALID()
        violated = self['violated-directive']
        blocked = self['blocked-uri']
        generated = violated.generateDirective(reportType, blocked)
        if generated == Directive.INVALID():
            return Policy.INVALID()
        else:
            return Policy((generated,))
        
    def __iter__(self):
        return iter(self._repData)
    
    def __len__(self):
        return len(self._repData)
    
    def __getitem__(self, key):
        return self._repData[key]
    
    def __eq__(self, other):
        """
        Returns if this report is equal to another report. This is implemented component-wise.
        """
        if type(other) != Report:
            return False
        return self._repData == other._repData
    
    def __hash__(self):
        """
        Returns a hash value for this object that is guaranteed to be the same for two objects
        that are equal (the opposite is not necessarily true).
        """
        if self._hash is None:
            self._hash = reduce(lambda hashSoFar, pair: hashSoFar ^ hash(pair), self._repData.iteritems(), 0)
        return self._hash
    
    def __repr__(self):
        """
        Returns a full representation of this Report. Equivalent to __str__().
        """
        return str(self)
        
    def __str__(self):
        """
        Returns a JSON representation of this CSP violation report with keys ordered alphabetically.
        """
        if self._str is None:
            if self == Report.INVALID():
                self._str = "[invalid]"
            else:
                self._str = json.dumps(self._repData, sort_keys=True, cls=ReportJSONEncoder)
        return self._str
    

class ReportParser(object):
    """
    Pre-configured object that parses strings or JSON dictionaries into Reports.
    """
    
    def __init__(self, 
                 uriKeys=defaults.uriKeys,
                 directiveKeys=defaults.directiveKeys,
                 policyKeys=defaults.policyKeys,
                 keyNameReplacements=defaults.reportKeyNameReplacements,
                 requiredKeys=defaults.requiredReportKeys,
                 strict=True,
                 addSchemeToURIs=False,
                 defaultURIScheme=defaults.defaultURIScheme,
                 addPortToURIs=False,
                 defaultURIPort=defaults.defaultURIPort,
                 schemePortMappings=defaults.schemePortMappings,
                 portSchemeMappings=defaults.portSchemeMappings,
                 directiveTypeTranslations=defaults.directiveTypeTranslations, 
                 allowedDirectiveTypes=defaults.allowedDirectiveTypes,
                 ignoredDirectiveTypes=defaults.ignoredDirectiveTypes,
                 expandDefaultSrc=False,
                 defaultSrcTypes=defaults.defaultSrcReplacementDirectiveTypes):
        """
        Creates a new ReportParser object configured with the following parameters:
        
        'uriKeys': an iterable of key (entry) names of which the corresponding values, if present,
                            will be parsed and replaced with an URI object.
        'directiveKeys': an iterable of key (entry) names of which the corresponding values, if present,
                            will be parsed and replaced with a Directive object.
        'policyKeys': an iterable of key (entry) names of which the corresponding values, if present,
                            will be parsed and replaced with a Policy object.
        The 'uriKeys', 'directiveKeys', and 'policyKeys' lists are mutually exclusive (a key may appear
                            in at most one of these lists.)
                            
        'keyNameReplacements': a dictionary of old key (entry) names mapped to the new name to be given
                            to them before any further parsing. This can be used to adjust to renamed 
                            fields in the violation reports generated by different browser versions.
        'requiredKeys': an iterable of key (entry) names that are mandatory and must appear in the report
                            with a valid value (if parsed, cannot be URI.INVALID()/Directive.INVALID()/
                            Policy.INVALID()). If this constraint is violated, the parsing result will be
                            Report.INVALID() (independent of the 'strict' setting). This restriction is 
                            applied after performing key name replacement.
        'strict': whether a parsing error of a child element should be ignored if it can be fixed (if
                            set to False, invalid children will be skipped), or if any parsing error
                            should cause the Report to become Report.INVALID() (if set to True).
        
        'addSchemeToURIs': [for parsed URIs] whether to add the scheme. (See URIParser for details.)
        'defaultURIScheme': [for parsed URIs] if the scheme should be added, the default scheme to be 
                            assumed if nothing can be inferred from the port. (See URIParser for details.)
        'addPortToURIs': [for parsed URIs] whether to add the port. (See URIParser for details.)
        'defaultURIPort': [for parsed URIs] if the port should be added, the default port to be assumed
                            if nothing can be inferred from the scheme. (See URIParser for details.)
        'schemePortMappings': [for parsed URIs and policy/directive parsing] A map from scheme names to the 
                            corresponding default port, or None if the scheme does not use ports. Any scheme
                            that may appear inside an URI, source expression, directive or policy should be
                            listed. (See URIParser and SourceExpressionParser for details.)
        'portSchemeMappings': [for parsed URIs] A map from port numbers to scheme names (only for "real" ports).
                            See URIParser for details.
        'directiveTypeTranslations': [for parsed directives and policies] A map from the old directive name to
                            the new name to be used. (See DirectiveParser for details.)
        'allowedDirectiveTypes': [for parsed directives and policies] a list of directive types that are allowed.
                            (See DirectiveParser or PolicyParser for details.)
        'ignoredDirectiveTypes': [for parsed policies] a list of directive types that are ignored when parsing
                            policies. (See PolicyParser for details.)
        'expandDefaultSrc': [for parsed policies] if set to True, each "default-src" directive in a parsed policy
                            will be expanded to the corresponding elementary directive types, if not yet present.
                            (See PolicyParser for details.)
        'defaultSrcTypes': [for parsed policies] when "default-src" is expanded, the elementary directive types
                            that will be added to replace the default policy. (See PolicyParser for details.)
        """
        self._strict = strict
        self._uriKeys = uriKeys
        self._directiveKeys = directiveKeys
        self._policyKeys = policyKeys
        self._keyNameReplacements = keyNameReplacements
        self._requiredKeys = requiredKeys
        
        self._uriParser = URIParser(addSchemeToURIs, defaultURIScheme, addPortToURIs, defaultURIPort,
                                    schemePortMappings, portSchemeMappings, True)
        self._directiveParser = DirectiveParser(directiveTypeTranslations, allowedDirectiveTypes, 
                                    schemePortMappings.keys(), strict)
        self._policyParser = PolicyParser(directiveTypeTranslations, allowedDirectiveTypes, ignoredDirectiveTypes, 
                                    schemePortMappings.keys(), strict, expandDefaultSrc, defaultSrcTypes)
    
    def parseString(self, stringReport):
        """
        Parses the given 'stringReport' according to the parameters set in the constructor of this ReportParser 
        and returns a Report object. 'stringReport' is expected to be a JSON-serialised map with attribute names
        and values corresponding to the definition of CSP violation reports. If 'stringReport' cannot be parsed 
        because it is syntactically invalid (or empty), Report.INVALID() will be returned.

        Depending on the configuration of this ReportParser object, some attributes will be parsed to replace their
        plain string values with a more high-level object representation.
        """
        try:
            jsonDict = json.loads(stringReport)
            return self.parseJsonDict(jsonDict)
        except ValueError:
            return Report.INVALID()
    
    def parseJsonDict(self, jsonReport):
        """
        Parses the given 'jsonReport' according to the parameters set in the constructor of this ReportParser 
        and returns a Report object. 'jsonReport' is expected to be a Python dict object with attribute names
        and values corresponding to the definition of CSP violation reports. If 'jsonReport' cannot be parsed 
        because it is syntactically invalid (or empty), Report.INVALID() will be returned.

        Depending on the configuration of this ReportParser object, some attributes will be parsed to replace their
        plain string values with a more high-level object representation.
        """
        
        # replace names
        renamedReport = dict(map(lambda (key, val): (self._replaceName(key), val), jsonReport.iteritems()))
                
        # convert data in report
        convertedReport = {}
        deferredSelfURIs = set([]) # all key names that have URIs that are exactly 'self' (handle after parsing everything else)
        for (key, value) in renamedReport.iteritems():
            if key in self._uriKeys:
                if value.lower().strip() == "self":
                    deferredSelfURIs.add(key)
                    continue
                else:
                    value = self._uriParser.parse(value)
            elif key in self._directiveKeys:
                value = self._directiveParser.parse(value)
            elif key in self._policyKeys:
                value = self._policyParser.parse(value)
            
            if value in (URI.INVALID(), Directive.INVALID(), Policy.INVALID()):
                if self._strict:
                    return Report.INVALID()
                else:
                    continue
            convertedReport[key] = value
            
        # handle deferred parsing of 'self' URIs (they represent the document-uri)
        for key in deferredSelfURIs:
            if "document-uri" in self._uriKeys and "document-uri" in convertedReport:
                convertedReport[key] = convertedReport["document-uri"]
            elif self._strict:
                return Report.INVALID()
            
        for requiredKey in self._requiredKeys:
            if not requiredKey in convertedReport:
                return Report.INVALID()
        return Report(convertedReport)

    def _replaceName(self, oldName):
        oldName = oldName.lower()
        if oldName in self._keyNameReplacements:
            return self._keyNameReplacements[oldName]
        else:
            return oldName

