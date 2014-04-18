'''
Represents one directive (that can be part of a CSP policy). A directive consists
of a list of whitelisted SourceExpressions (which can be empty, corresponding to 'none').
'DirectiveParser' can be used to parse Directives from strings.

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''

from sourceexpression import SourceExpressionParser, SourceExpression, URISourceExpression
from uri import URI
import defaults


class Directive(object):
    """A single CSP directive ("rule"). Immutable"""
    
    _invalid = None
    _inlineStyleBaseRestriction = None
    _inlineScriptBaseRestriction = None
    _evalScriptBaseRestriction = None
    
    def __init__(self, directiveType, whitelistedSourceExpressions):
        """
        Initialises this CSP directive from the given 'directiveType' and 'whitelistedSourceExpressions'.
        
        'directiveType' is a CSP directive type that accepts a set/list of source expressions. Supported values
        are: "default-src", "script-src", "object-src", "style-src", "img-src", "media-src", "frame-src", 
        "font-src", "connect-src".
        
        'whitelistedSourceExpressions' is a list or tuple or set of SourceExpressions that are associated with the
        given directive. It can be empty (but not None) to represent the 'none' source expression. Duplicate
        source expressions are ignored. There can be at most one SourceExpression of the 'self' type. Any source
        expression that is SourceExpression.INVALID() will be dropped.
        """
        self._hash = None
        self._str = None
        self._directiveType = directiveType
        whitelistedSrcExpr = set(filter(lambda x: x != SourceExpression.INVALID(), whitelistedSourceExpressions))
        self._whitelistedSourceExpressions = frozenset(whitelistedSrcExpr)
        self._isRegularDirective = True
        
    @staticmethod
    def INVALID():
        """
        Special static singleton Directive representing an invalid directive (could not be parsed).
        """
        if Directive._invalid is None:
            Directive._invalid = Directive("[invalid]", ())
            Directive._invalid._isRegularDirective = False
        return Directive._invalid
    
    @staticmethod
    def INLINE_STYLE_BASE_RESTRICTION():
        """
        Special static singleton Directive representing the Firefox "inline style base restriction"
        value for the "violated-directive" field in CSP violation reports.
        """
        if Directive._inlineStyleBaseRestriction is None:
            Directive._inlineStyleBaseRestriction = Directive("[inline style base restriction]", ())
            Directive._inlineStyleBaseRestriction._isRegularDirective = False
        return Directive._inlineStyleBaseRestriction
    
    @staticmethod
    def INLINE_SCRIPT_BASE_RESTRICTION():
        """
        Special static singleton Directive representing the Firefox "inline script base restriction"
        value for the "violated-directive" field in CSP violation reports.
        """
        if Directive._inlineScriptBaseRestriction is None:
            Directive._inlineScriptBaseRestriction = Directive("[inline script base restriction]", ())
            Directive._inlineScriptBaseRestriction._isRegularDirective = False
        return Directive._inlineScriptBaseRestriction
    
    @staticmethod
    def EVAL_SCRIPT_BASE_RESTRICTION():
        """
        Special static singleton Directive representing the Firefox "eval script base restriction"
        value for the "violated-directive" field in CSP violation reports.
        """
        if Directive._evalScriptBaseRestriction is None:
            Directive._evalScriptBaseRestriction = Directive("[eval script base restriction]", ())
            Directive._evalScriptBaseRestriction._isRegularDirective = False
        return Directive._evalScriptBaseRestriction
    
    def isRegularDirective(self):
        """
        Returns whether this directive is regular directive (not INVALID() or any of the other special
        singleton types).
        """
        return self._isRegularDirective
    
    def combinedDirective(self, otherDirective):
        """
        Returns a new Directive that is the combination of this Directive and the 'otherDirective'
        with both whitelists combined (that is, a more permissive combined whitelist). This method
        can be used when generating directives/policies from violation reports, but should not be
        used to enforce multiple directives of the same type (the semantics are different).
        
        If the types of this and 'otherDirective' are different, or if this or 'otherDirective' is
        not a regular directive, then Directive.INVALID() is returned.
        
        This implementation does NOT perform any extended matching for URIs (that is, duplicate
        URIs are removed only if they are identical, but not when one contains a scheme/port, for
        instance, and the other does not). The implementation does not attempt to replace any URI
        with the 'self' keyword either.
        """
        if (not self.isRegularDirective()
            or not otherDirective.isRegularDirective()):
            return Directive.INVALID()
        dirType = self.getType()
        if otherDirective.getType() != dirType:
            return Directive.INVALID()
        return Directive(dirType, self._whitelistedSourceExpressions | otherDirective._whitelistedSourceExpressions)
    
    def getType(self):
        """
        Returns the type of the directive: default-src, script-src, object-src, style-src,
        img-src, media-src, frame-src, font-src, connect-src.
        """
        if self == Directive.INLINE_STYLE_BASE_RESTRICTION():
            return "style-src"
        elif self == Directive.INLINE_SCRIPT_BASE_RESTRICTION():
            return "script-src"
        elif self == Directive.EVAL_SCRIPT_BASE_RESTRICTION():
            return "script-src"
        else:
            return self._directiveType
    
    def getWhitelistedSourceExpressions(self):
        """
        Returns a frozen set of all the whitelisted source expressions in this directive.
        """
        return self._whitelistedSourceExpressions # already immutable
    
    def matches(self, resourceURI, protectedDocumentURI, schemePortMappings=defaults.schemePortMappings):
        """
        Returns whether the given resourceURI is allowed under this directive.
        
        'resourceURI' is an URI object corresponding to the resource that is attempted to be loaded/executed.
        Can be either one of the special URI.UNSAFE_EVAL() / URI.UNSAFE_INLINE() URIs, or a regular URI.
        In the latter case, escaped characters in the path of the URI should already have been decoded. 
        If 'resourceURI' designates a directory (as opposed to a file), its path must end with a '/'. 
        May not be None. It is assumed that the type of the resource associated with 'resourceURI' is of 
        the same type as this Directive.
        
        'protectedDocumentURI' is the URI of the document in the context of which 'resourceURI' is being 
        attempted to be loaded/executed (the host document). May not be None.
        
        'schemePortMappings': A dictionary with mappings from (lowercase) scheme names to the corresponding
        default port. Will be used if ports are missing in the 'resourceURI' or 'protectedDocumentURI'. 
        
        This implementation requires schemes to be present in both URIs, and either port numbers or a successful
        scheme-to-port-number look up in 'schemePortMappings' for both URIs (otherwise, False is returned).
        For details about the implementation, see http://www.w3.org/TR/2014/WD-CSP11-20140211/#matching
        """
        if not self.isRegularDirective():
            return False
        for srcExpr in self._whitelistedSourceExpressions:
            if srcExpr.matches(resourceURI, protectedDocumentURI, schemePortMappings):
                return True
        return False
    
    def generateDirective(self, reportType, blockedURI):
        """
        Generates a new Directive that allows exactly the kind of event that caused the CSP violation report,
        assuming this Directive ('self') was the 'violated-directive' in a report of the given 'reportType' 
        (permitted values are 'regular', 'eval', and 'inline'), and 'blockedURI' was the value of the report 
        field 'blocked-uri'.
        
        This directive may not be of the type 'default-src'. The result of this method is a Directive. It is 
        Directive.INVALID() if (1) the type of this Directive is 'default-src' (or it is Directive.INVALID()), 
        or a special type incompatible with 'reportType', (2) if 'reportType' is none out of 'regular', 
        'inline' or 'eval', (3) the 'blocked-uri' is URI.INVALID() or not a regular URI in the 
        'reportType'=='regular' case [old], or a regular URI in the 'eval' or 'inline' cases[/old].
        
        This implementation does not handle URIs in any special way. That is, it does
        not add or remove ports, path/query components, or replace them with the 'self' keyword.
        """
        if (self == Directive.INVALID()
            or (self == Directive.EVAL_SCRIPT_BASE_RESTRICTION() and reportType != 'eval')
            or (self == Directive.INLINE_SCRIPT_BASE_RESTRICTION() and reportType != 'inline')
            or (self == Directive.INLINE_STYLE_BASE_RESTRICTION() and reportType != 'inline')
            or self.getType() == "default-src"
            or reportType not in ('regular', 'eval', 'inline')
            or blockedURI == URI.INVALID()
            or (reportType == 'regular' and not blockedURI.isRegularURI())
#             or (reportType in ('eval', 'inline') and blockedURI.isRegularURI())
            or (reportType == 'eval' and self.getType() != 'script-src')
            or (reportType == 'inline' and self.getType() not in ('script-src', 'style-src'))):
            return Directive.INVALID()
        
        generated = Directive.INVALID()
        if reportType == 'regular':
            generated = Directive(self.getType(), 
                                  (URISourceExpression(blockedURI.getScheme(), blockedURI.getHost(), 
                                                       blockedURI.getPort(), blockedURI.getPath()),))
        elif reportType == 'eval':
            generated = Directive(self.getType(),
                                  (SourceExpression.UNSAFE_EVAL(),))
        elif reportType == 'inline':
            generated = Directive(self.getType(),
                                  (SourceExpression.UNSAFE_INLINE(),))
        return generated
    
    def withoutPaths(self, schemeOnly=defaults.schemeOnly):
        """
        Returns a copy of this Directive that has the path components removed from all contained
        URISourceExpressions.
        
        'schemeOnly' is a list of scheme names. If the scheme of any source expression is contained
        in this list, not only the path will be removed, but the host and port, too. This is useful
        for data or chrome-extension URIs, for example.
        """
        if not self.isRegularDirective():
            return self
        srcExpressions = []
        for srcExpr in self._whitelistedSourceExpressions:
            if srcExpr.getType() == "uri":
                if srcExpr.getScheme() is not None and srcExpr.getScheme() in schemeOnly:
                    srcExpressions.append(srcExpr.schemeOnly())
                else:
                    srcExpressions.append(srcExpr.removePath())
            else:
                srcExpressions.append(srcExpr)
        return Directive(self._directiveType, srcExpressions)
    
    def asBasicDirectives(self):
        """
        Returns a set of Directives that each contain exactly one SourceExpression (derived from this
        Directive), or the empty set if this Directive is not regular.
        """
        if not self.isRegularDirective():
            return set([])
        if len(self._whitelistedSourceExpressions) <= 1:
            return frozenset((self,))
        directives = set([])
        for srcExpr in self._whitelistedSourceExpressions:
            directives.add(Directive(self._directiveType, (srcExpr,)))
        return directives
    
    def isBasicDirective(self):
        """
        Returns whether this Directive is basic. That is, whether it has a whitelisted resources list
        of length one or zero, and is a regular Directive.
        """
        if not self.isRegularDirective():
            return False
        else:
            return len(self._whitelistedSourceExpressions) <= 1
    
    def __repr__(self):
        """
        Returns a full representation of this Directive. Equivalent to __str__().
        """
        return str(self)
    
    def __str__(self):
        """
        Returns a string representation of this directive (with source expressions sorted).
        """
        if self._str is None:
            if self == Directive.INVALID():
                self._str = "[invalid]"
            elif self == Directive.INLINE_STYLE_BASE_RESTRICTION():
                self._str = "inline style base restriction"
            elif self == Directive.INLINE_SCRIPT_BASE_RESTRICTION():
                self._str = "inline script base restriction"
            elif self == Directive.EVAL_SCRIPT_BASE_RESTRICTION():
                self._str = "eval script base restriction"
            elif len(self._whitelistedSourceExpressions) == 0:
                self._str = self._directiveType + " 'none'"
            else:
                strExpressions = map(lambda x: str(x), self._whitelistedSourceExpressions)
                strExpressions.sort()
                self._str = self._directiveType + " " + " ".join(strExpressions)
        return self._str

    def __eq__(self, other):
        """
        Checks if the two directives are the same (by recursively checking if the type and
        source expressions are equal). This does NOT check if both directives have the same 
        effect (which could happen if one uses default-src and the other specifies all elementary
        types, for instance).
        """
        if type(other) != Directive:
            return False
        if self._isRegularDirective != other._isRegularDirective:
            return False
        if self._directiveType != other._directiveType:
            return False
        if self._whitelistedSourceExpressions != other._whitelistedSourceExpressions:
            return False
        return True
    
    def __hash__(self):
        """
        Returns a hash value for this object that is guaranteed to be the same for two objects
        that are equal (the opposite is not necessarily true).
        """
        if self._hash is None:
            self._hash = hash(self._directiveType) ^ hash(self._whitelistedSourceExpressions) ^ hash(self._isRegularDirective)
        return self._hash


class DirectiveParser(object):
    """
    Pre-configured object that parses strings into Directives.
    """
    
    def __init__(self, 
                 typeTranslations=defaults.directiveTypeTranslations, 
                 allowedTypes=defaults.allowedDirectiveTypes,
                 knownSchemes=defaults.supportedSchemes,
                 strict=True):
        """
        Creates a new DirectiveParser object configured with the following parameters:
        'typeTranslations': a map from directive types to another directive type. Used to convert old names
        to the new name. All lowercase.
        'allowedTypes': a list of (lowercase) directive types that are allowed. (Parsing other types will result in 
        Directive.INVALID().)
        'knownSchemes': For parsing source expressions. A list of all schemes that are supported. (Others may
        result in errors or Directive.INVALID().) All lowercase.
        'strict': if set to True, parsing errors of the directive or source expressions contained therein will
        be fixed by ignoring the invalid portion. Otherwise, any parsing error will result in Directive.INVALID().
        """
        self._typeTranslations = typeTranslations.copy()
        self._allowedTypes = allowedTypes
        self._sourceExpressionParser = SourceExpressionParser(knownSchemes)
        self._strict = strict
    
    def parse(self, stringDirective):
        """
        Parses the given 'stringDirective' according to the parameters set in the constructor of this DirectiveParser 
        and returns a Directive object. If 'stringDirective' cannot be parsed because it is syntactically invalid (or empty),
        Directive.INVALID() will be returned. (A directive cannot consist of only whitespace.)

        Depending on the configuration of this DirectiveParser object, may perform internal translation of the type 
        and filter certain directive types (returns Directive.INVALID() in that case).
        """
        
        # extract/translate directive type
        stringDirective = stringDirective.strip()
        if stringDirective == "inline style base restriction":
            return Directive.INLINE_STYLE_BASE_RESTRICTION()
        elif stringDirective == "inline script base restriction":
            return Directive.INLINE_SCRIPT_BASE_RESTRICTION()
        elif stringDirective == "eval script base restriction":
            return Directive.EVAL_SCRIPT_BASE_RESTRICTION()
        
        directiveParts = stringDirective.partition(" ")
        if directiveParts[0] == stringDirective:
            return Directive.INVALID() # could not split as expected (no " ")
        directiveType = directiveParts[0].strip().lower()
        if directiveType in self._typeTranslations:
            directiveType = self._typeTranslations[directiveType]
        if directiveType == "" or directiveType not in self._allowedTypes:
            return Directive.INVALID() # parsing error or type not allowed (e.g., report-uri or sandbox)

        # extract whitelisted source expressions
        whitelistedResources = directiveParts[2].strip().split()
        
        # handle 'none' in list
        # (list of length 0 might be invalid, but we handle it as 'none', too)
        if ("'none'" in map(lambda x: x.lower(), whitelistedResources)
            and len(whitelistedResources) > 1 
            and self._strict):
            return Directive.INVALID() # 'none' must be only resource if present
        
        # clean up URIs (and make unique set)
        validWhitelistedSourceExpressions = set([])
        for res in whitelistedResources:
            if res.lower() == "'none'":
                continue
            srcExpr = self._sourceExpressionParser.parse(res)
            # check some error conditions
            if srcExpr == SourceExpression.INVALID():
                if self._strict:
                    return Directive.INVALID()
                else:
                    continue
            if srcExpr == SourceExpression.UNSAFE_EVAL() and not directiveType in ("script-src", "default-src"):
                if self._strict:
                    return Directive.INVALID()
                else:
                    continue
            if srcExpr == SourceExpression.UNSAFE_INLINE() and not directiveType in ("script-src", "style-src", "default-src"):
                if self._strict:
                    return Directive.INVALID()
                else:
                    continue
            validWhitelistedSourceExpressions.add(srcExpr)
        return Directive(directiveType, validWhitelistedSourceExpressions)

