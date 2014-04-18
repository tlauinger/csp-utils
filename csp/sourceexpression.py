'''
SourceExpression objects appear in Directive whitelists and represent sources from
which a certain type of resource is allowed to be loaded. SourceExpressions can be based
either on URIs ('URISourceExpression'), the 'self' keyword ('SelfSourceExpression'), or
the 'unsafe-inline'/'unsafe-eval' keywords (represented by the UNSAFE_INLINE() and
UNSAFE_EVAL() class methods of 'SourceExpression', respectively). The two remaining types 
of source expressions in the CSP 1.1 draft, nonce-source and hash-source, are not currently 
supported.SourceExpressions can be parsed from strings using 'SourceExpressionParser'.

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''

from uri import URI, URIParser
import re
import urllib
import defaults

class SourceExpression(object):
    """
    A source expression according to Section 3.2.2 of the CSP 1.1 draft specification
    http://www.w3.org/TR/2014/WD-CSP11-20140211/
    
    It is essentially a URI with the wildcard * allowed in certain places, and specific
    matching rules, or one of a few special keywords. This source expression appears in 
    whitelists of CSP directives.
    
    In this implementation, a source expression can be either:
    (1) a scheme-source (scheme ":")
    (2) a host-source ([ scheme "://" ] host [ port ] [ path ])
        with host either "*" or a regular domain name, optionally prepended by "*.", and
        port either "*" or a number
    (3) a keyword-source ("'self'" / "'unsafe-inline'" / "'unsafe-eval'")
    The two remaining types of source expressions in the CSP 1.1 draft, nonce-source and 
    hash-source, are not currently supported.
    
    SourceExpression objects allow URIs to be tested for matching. The rules for matching
    are explained in the CSP specification. There are three special cases:
    (1) 'self' matches URIs according to the scheme, host and port configured in the 
    SourceExpressionParser used to generate this SourceExpression. 
    (2) 'unsafe-inline' and (3) 'unsafe-eval' match only the special URIs URI.UNSAFE_INLINE()
    and URI.UNSAFE_EVAL(), respectively.
    
    This generic SourceExpression type is used only for the 'unsafe-inline' and 'unsafe-eval'
    and '[invalid]' singletons; other types of SourceExpressions are implemented in subtypes.
    
    Immutable.
    """
    
    _unsafeInline = None
    _unsafeEval = None
    _invalid = None

    def __init__(self, exprType):
        '''
        "Abstract" constructor that accepts only the type of this SourceExpression.
        'exprType' is either "uri", "unsafe-inline", "unsafe-eval" or "self" (see getType()).
        This constructor should not be called directly (use SourceExpressionParser instead,
        or call one of the static singleton methods).
        '''
        self._hash = None
        self._str = None
        self._type = exprType.lower()
        
    @staticmethod
    def UNSAFE_INLINE():
        """
        Special static singleton SourceExpression representing the 'unsafe-inline' expression.
        """
        if SourceExpression._unsafeInline is None:
            SourceExpression._unsafeInline = SourceExpression("unsafe-inline")
        return SourceExpression._unsafeInline
    
    @staticmethod
    def UNSAFE_EVAL():
        """
        Special static singleton SourceExpression representing the 'unsafe-eval' expression.
        """
        if SourceExpression._unsafeEval is None:
            SourceExpression._unsafeEval = SourceExpression("unsafe-eval")
        return SourceExpression._unsafeEval
    
    @staticmethod
    def INVALID():
        """
        Special static singleton SourceExpression representing the "invalid" expression.
        """
        if SourceExpression._invalid is None:
            SourceExpression._invalid = SourceExpression("[invalid]")
        return SourceExpression._invalid
    
    def getType(self):
        """
        Returns the type of this SourceExpression, which is either "uri" (for grammar types (1) and (2)), 
        "self", "unsafe-inline" or "unsafe-eval" (grammar type (3)), or "[invalid]" for source expression
        strings that could not be parsed successfully.
        """
        return self._type
    
    def matches(self, resourceURI, protectedDocumentURI, schemePortMappings=defaults.schemePortMappings):
        """
        Returns whether the given resourceURI matches this source expression.
        
        'resourceURI' is an URI object corresponding to the resource that is attempted to be loaded/executed.
        Can be either one of the special URI.UNSAFE_EVAL() / URI.UNSAFE_INLINE() URIs, or a regular URI.
        In the latter case, escaped characters in the path of the URI should already have been decoded. 
        If 'resourceURI' designates a directory (as opposed to a file), its path must end with a '/'. 
        May not be None.
        
        'protectedDocumentURI' is the URI of the document in the context of which 'resourceURI' is being 
        attempted to be loaded/executed (the host document). May not be None.
        
        'schemePortMappings': A dictionary with mappings from (lowercase) scheme names to the corresponding
        default port. Will be used if ports are missing in the 'resourceURI' or 'protectedDocumentURI'. 
        
        This implementation requires schemes to be present in both URIs, and either port numbers or a successful
        scheme-to-port-number look up in 'schemePortMappings' for both URIs (otherwise, False is returned).
        For details about the implementation, see http://www.w3.org/TR/2014/WD-CSP11-20140211/#matching
        """
        if self == SourceExpression.UNSAFE_EVAL() and resourceURI == URI.EVAL():
            return True
        elif self == SourceExpression.UNSAFE_INLINE() and resourceURI == URI.INLINE():
            return True
        return False
    
    def __repr__(self):
        """
        Returns a full representation of this URI. Equivalent to __str__().
        """
        return str(self)
    
    def __str__(self):
        """
        Returns a string representation of this source expression.
        """
        if self._str is None:
            if self._type == "unsafe-inline":
                self._str = "'unsafe-inline'"
            elif self._type == "unsafe-eval":
                self._str = "'unsafe-eval'"
            elif self._type == "[invalid]":
                self._str = "[invalid]"
            else:
                self._str = "<?>"
        return self._str
    
    def __eq__(self, other):
        """
        Returns True if both objects represent the same SourceExpression (here only for unsafe-inline and
        unsafe-eval types). 'uri' should be an URI object with escaped characters already
        decoded.
        """
        if type(other) != SourceExpression:
            return False
        return other._type == self._type
    
    def __hash__(self):
        """
        Returns a hash value for this object that is guaranteed to be the same for two objects
        that are equal (the opposite is not necessarily true).
        """
        if self._hash is None:
            self._hash = hash(self._type)
        return self._hash
    

class SelfSourceExpression(SourceExpression):
    """
    SourceExpression for 'self'-style expressions. Immutable.
    This constructor should not be called directly (use SourceExpressionParser instead,
    or call the static singleton method SelfSourceExpression.SELF()).
    """
    
    _self = None
    
    def __init__(self):
        """
        Constructs a new SelfSourceExpression.
        """
        SourceExpression.__init__(self, "self")
        
    @staticmethod
    def SELF():
        """
        Special static singleton SelfSourceExpression representing the 'self' expression.
        """
        if SelfSourceExpression._self is None:
            SelfSourceExpression._self = SelfSourceExpression()
        return SelfSourceExpression._self
        
    def matches(self, resourceURI, protectedDocumentURI, schemePortMappings=defaults.schemePortMappings):
        """
        See documentation of super class SourceExpression.matches(.).
        """
        if not resourceURI.isRegularURI():
            return False
        
        if protectedDocumentURI.getScheme() is None or resourceURI.getScheme() is None:
            return False
        
        myPort = protectedDocumentURI.getPort()
        if myPort is None:
            myPort = self._getPort(protectedDocumentURI.getScheme(), schemePortMappings)
        if myPort is None:
            return False
        
        otherPort = resourceURI.getPort()
        if otherPort is None:
            otherPort = self._getPort(resourceURI.getScheme(), schemePortMappings)
        if otherPort is None:
            return False
        
        return (protectedDocumentURI.getScheme() == resourceURI.getScheme()
                and protectedDocumentURI.getHost() == resourceURI.getHost()
                and myPort == otherPort)
    
    def __str__(self):
        """
        Returns a string representation of this source expression.
        """
        if self._str is None:
            self._str = "'self'"
        return self._str
    
    def __eq__(self, other):
        """
        Returns True if both objects represent the same SourceExpression (here only for the self type).
        """
        if type(other) != SelfSourceExpression:
            return False
        return True
    
    def __hash__(self):
        """
        Returns a hash value for this object that is guaranteed to be the same for two objects
        that are equal (the opposite is not necessarily true).
        """
        if self._hash is None:
            self._hash = 424242
        return self._hash
    
    def _getPort(self, scheme, schemePortMappings):
        if scheme.lower() in schemePortMappings:
            return schemePortMappings[scheme.lower()]
        else:
            return None
        

class URISourceExpression(SourceExpression):
    """
    SourceExpression for the "scheme:" and "host"-style expressions. Immutable.
    """
    
    def __init__(self, scheme, host, port, path):
        """
        Constructs a new URISourceExpression (of the "scheme:" and "host" grammar types).
        
        'scheme': A non-empty string representing a scheme, or None.
        'host': A non-empty string representing a host, or None. The wildcard '*' is allowed
        for either the entire host or subdomains as defined in the CSP 1.1 draft.
        'path': A non-empty unicode string with special characters decoded (no %-encoding),
        beginning with '/', or None.
        'port' is either None or an integer or the '*' string.
        
        Examples:
        1. URISourceExpression("chrome-extension", None, None, None) corresponds to "chrome-extension:"
        2. URISourceExpression("http", "seclab.nu", "*", "/file") corresponds to "http://seclab.nu:*/file"
        3. URISourceExpression(None, "*", 443, None) corresponds to "*:443"
        """
        SourceExpression.__init__(self, "uri")
        self._scheme = self._makeEmptyNone(scheme)
        if self._scheme is not None:
            self._scheme = self._scheme.lower()
        self._host = self._makeEmptyNone(host)
        if self._host is not None:
            self._host = self._host.lower()
        self._port = port
        self._path = self._makeEmptyNone(path)
        
    def getScheme(self):
        """Returns the scheme of this URISourceExpression (None or a string)."""
        return self._scheme
    
    def getHost(self):
        """Returns the host of this URISourceExpression (None or a string)."""
        return self._host
    
    def getPort(self):
        """Returns the port of this URISourceExpression (None or an integer or the '*' string)."""
        return self._port
    
    def getPath(self):
        """Returns the path of this URISourceExpression (None or a unicode string)."""
        return self._path
        
    def matches(self, resourceURI, protectedDocumentURI, schemePortMappings=defaults.schemePortMappings):
        """
        See documentation of super class SourceExpression.matches(.).
        """
        if not resourceURI.isRegularURI():
            return False
        
        # only *
        if self._scheme is None and self._host == "*" and self._port is None and self._path is None:
            return True
        
        # only scheme:
        uriScheme = resourceURI.getScheme()
        if uriScheme is not None:
            uriScheme = uriScheme.lower()
        if (self._scheme is not None 
            and self._scheme == uriScheme
            and self._host is None 
            and self._port is None 
            and self._path is None):
            return True
        
        uriHost = resourceURI.getHost()
        if uriHost is None:
            return False
        uriHost = uriHost.lower()
        uriPort = resourceURI.getPort()
        if uriPort is None and uriScheme is not None and uriScheme in schemePortMappings:
            uriPort = schemePortMappings[uriScheme]
        uriPath = resourceURI.getPath()
        if uriPath is None or uriPath == "":
            uriPath = "/"
        
        if self._scheme is not None and self._scheme != uriScheme:
            return False

        protectedURIScheme = protectedDocumentURI.getScheme().lower()
        if self._scheme is None and protectedURIScheme == "http" and uriScheme not in ('http', 'https'):
            return False
        if self._scheme is None and protectedURIScheme != "http" and protectedURIScheme != uriScheme:
            return False
        
        if self._host is not None and self._host[0] == "*" and len(self._host) > 1 and self._host[1:] != uriHost[-len(self._host)+1:]:
            return False
        
        if self._host is not None and self._host[0] != "*" and self._host != uriHost:
            return False

        if self._port is None and uriScheme is not None and uriScheme in schemePortMappings and uriPort != schemePortMappings[uriScheme]:
            return False
        
        if self._port is not None and self._port != '*' and int(self._port) != int(uriPort):
            return False
        
        if self._path is not None and uriPath is not None and self._path[-1:] == '/' and self._path != uriPath[:len(self._path)]:
            return False
        if self._path is not None and uriPath is not None and self._path[-1:] != '/' and self._path != uriPath:
            return False
        
        return True
    
    def removePath(self):
        """
        Returns a copy of this URISourceExpression without the path component.
        """
        return URISourceExpression(self._scheme, self._host, self._port, None)
    
    def schemeOnly(self):
        """
        Returns a copy of this URISourceExpression with only the scheme. If the scheme
        is not set, returns SourceExpression.INVALID().
        """
        if self._scheme is None:
            return SourceExpression.INVALID()
        else:
            return URISourceExpression(self._scheme, None, None, None)
    
    def __str__(self):
        """
        Returns a string representation of this source expression.
        """
        if self._str is None:
            if self._scheme is not None and self._host is None and self._port is None and self._path is None:
                self._str = self._scheme + ":"
            else:
                self._str = ""
                if self._scheme is not None:
                    self._str += self._scheme + "://"
                if self._host is not None:
                    self._str += self._host
                if self._port is not None:
                    self._str += ":" + str(self._port)
                if self._path is not None:
                    self._str += urllib.quote(self._path.encode('utf8')).decode('ascii')
        return self._str
    
    def __eq__(self, other):
        """
        Returns True if both objects represent the same SourceExpression (here only for the "scheme:" and
        "host"-style types). Comparison is done by comparing all fields for equality. This does NOT check 
        if both URISourceExpressions have the same effect (which could be the case when omitting port 
        numbers, for instance).
        """
        if type(other) != URISourceExpression:
            return False
        return (other._scheme == self._scheme
                and other._host == self._host
                and other._port == self._port
                and other._path == self._path)
    
    def __hash__(self):
        """
        Returns a hash value for this object that is guaranteed to be the same for two objects
        that are equal (the opposite is not necessarily true).
        """
        if self._hash is None:
            self._hash = hash(self._scheme) ^ hash(self._host) ^ hash(self._port) ^ hash(self._path)
        return self._hash
        
    def _makeEmptyNone(self, string):
        if string == "":
            return None
        else:
            return string
        
        
class SourceExpressionParser(object):
    """
    A source expression parser transforms string representations of source expressions into
    objects. It is parameterised so that all strings parsed by the same parser object use the
    same parameters.
    """
    
    def __init__(self, knownSchemes=defaults.supportedSchemes):
        """
        Constructs a new SourceExpressionParser that converts strings to various kinds of 
        SourceExpression objects. The parameters given here determine some details of how
        source expressions are parsed.

        'knownSchemes' is a list or tuple of (lowercase) scheme names that are supported in source
        expressions. Schemes that are different will result in no SourceExpression being parsed
        (except for a lack of scheme, which is permitted).
        """
        self._knownSchemes = tuple(knownSchemes)
        self._parser = SourceExpressionURIParser()
    
    def parse(self, sourceExpressionString):
        """Parses the given 'sourceExpressionString' according to the parameters set in this object. Returns the
        appropriate type of SourceExpression, or SourceExpression.INVALID() in case of a parsing error."""
        sourceExpressionString = sourceExpressionString.strip()
        
        if sourceExpressionString.lower() == "'unsafe-eval'":
            return SourceExpression.UNSAFE_EVAL()
        elif sourceExpressionString.lower() == "'unsafe-inline'":
            return SourceExpression.UNSAFE_INLINE()
        elif sourceExpressionString.lower() == "'self'":
            return SelfSourceExpression.SELF()
        elif sourceExpressionString == "*":
            return URISourceExpression(None, "*", None, None)
        
        sourceExpressionParsedAsURI = self._parser.parse(sourceExpressionString)
        if sourceExpressionParsedAsURI == URI.EMPTY() or sourceExpressionParsedAsURI == URI.INVALID():
            return SourceExpression.INVALID()
        if sourceExpressionParsedAsURI.getScheme() is not None and sourceExpressionParsedAsURI.getScheme().lower() not in self._knownSchemes:
            return SourceExpression.INVALID()
        
        port = sourceExpressionParsedAsURI.getPort()
        if port not in ('*', None): # convert port if it should be a number
            port = int(sourceExpressionParsedAsURI.getPort())
        return URISourceExpression(sourceExpressionParsedAsURI.getScheme(), sourceExpressionParsedAsURI.getHost(), 
                                   port, sourceExpressionParsedAsURI.getPath())


class SourceExpressionURIParser(URIParser):
    """Internal class that is used as a helper to parse source expressions from strings. In addition to the
    regular URI format, source expressions allow * as the host and port, or *. subdomains in the host, but
    no user name or password components."""
    
    netlocRE = re.compile(r"""^(?P<host>\*|(\*\.)?[A-Za-z0-9._-]+)(:(?P<port>\*|[0-9]+))?$""", re.IGNORECASE)
    
    def __init__(self):
        URIParser.__init__(self, addScheme=False, addPort=False, decodeEscapedCharacters=True)
        self._convertPortToInt = False
    
    def _getRE(self):
        return SourceExpressionURIParser.netlocRE
    
