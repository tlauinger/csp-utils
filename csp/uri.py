'''
The 'URI' class represents URI objects consisting of a scheme, host, port, path and query.
Both typical URLs and a few less common URIs (such as 'data:', 'view-source:', 'chrome-extension:')
are supported. They can be parsed from strings using 'URIParser'.

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''

import urlparse
import re
import urllib
import defaults


class URI(object):
    """
    A URI as useful in the context of CSP. Immutable. There are a few special singleton URI types
    that can be accessed by calling the respective class method (INVALID(), EMPTY(), etc.).
    """
    
    _invalid = None
    _empty = None
    _inline = None
    _eval = None
    
    def __init__(self, scheme, host, port, path, query=None):
        """
        Constructs a new URI object from the given scheme, host, port and path components, and 
        optionally the query component.
        
        'scheme': The scheme name of the URI as a string (optional, may be None but not empty).
        'host': The host name of the URI as a string (may not be None or empty). The string should
        contain no special characters; if the original host name contains special characters, the
        name should be in punycode. In the case of some special schemes (such as 'data:', 'view-source:',
        and 'chrome-extension'), the host contains the encoded data/URL/extension ID, respectively.
        'port': An integer representing the port number. May be None to leave unspecified.
        'path': A unicode string representing the path component of the URI, including the leading '/'.
        May be None, but not empty. Special characters should be decoded rather than being %-encoded.
        'query': A string of the query component of the URI, without the '?'. Special characters
        should be %-encoded. May be None, should not be empty.
        
        Example: URI("http", "seclab.nu", 80, "/path", "param1=value")
        corresponds to "http://seclab.nu:80/path?param1=value".
        """
        self._hash = None
        self._str = None
        self._scheme = self._makeEmptyNone(scheme)
        self._host = host
        self._port = port
        self._path = self._makeEmptyNone(path)
        self._query = self._makeEmptyNone(query)
        self._isRegularURI = True
        
    @staticmethod
    def INVALID():
        """
        Special static singleton URI representing an invalid URI (e.g., URI could not be parsed).
        """
        if URI._invalid is None:
            URI._invalid = URI(None, "[invalid]", None, None, None)
            URI._invalid._isRegularURI = False
        return URI._invalid
    
    @staticmethod
    def EMPTY():
        """
        Special static singleton URI representing an unknown URI (e.g., the empty string).
        """
        if URI._empty is None:
            URI._empty = URI(None, "[empty]", None, None, None)
            URI._empty._isRegularURI = False
        return URI._empty
    
    @staticmethod
    def INLINE():
        """
        Special static singleton "fake" URI representing an inline style/script execution. This is not a "real"
        URI, but supposed to be used for SourceExpression/Directive/Policy matching.
        """
        if URI._inline is None:
            URI._inline = URI(None, "[inline]", None, None, None)
            URI._inline._isRegularURI = False
        return URI._inline
    
    @staticmethod
    def EVAL():
        """
        Special static singleton "fake" URI representing an eval (script) execution. This is not a "real"
        URI, but supposed to be used for SourceExpression/Directive/Policy matching.
        """
        if URI._eval is None:
            URI._eval = URI(None, "[eval]", None, None, None)
            URI._eval._isRegularURI = False
        return URI._eval   
    
    def getScheme(self):
        """
        Returns the scheme part of this URI, or None if not specified.
        """
        return self._scheme
    
    def getHost(self):
        """
        Returns the host part of this URI. (Or the data/URL in case of URIs using the 
        'data:'/'view-source:' or similar schemes.)
        """
        return self._host
    
    def getPort(self):
        """
        Returns the port part of this URI (as a number), if the scheme uses a port (and
        if a port is specified), or None.
        """
        return self._port
    
    def getPath(self):
        """
        Returns the path part of this URI including the leading '/', or None if not specified. 
        (As a unicode string.)
        """
        return self._path
    
    def getQuery(self):
        """
        Returns the query part of this URI, or None if not specified. (As a binary string,
        without the '?'.)
        """
        return self._query
    
    def isRegularURI(self):
        """
        Returns whether this is a "regular" URI, that is, valid, not empty, and not any "fake"
        placeholder URI.
        """
        return self._isRegularURI
    
    def removePath(self):
        """
        Returns a new URI object with the same data as this URI, except that the path component
        and the query component are set to None. (If this URI is not a regular URI, the same
        object is returned.)
        """
        if not self.isRegularURI():
            return self
        return URI(self._scheme, self._host, self._port, None, None)
    
    def __repr__(self):
        """
        Returns a full representation of this URI. Equivalent to __str__().
        """
        return str(self)
    
    def __str__(self):
        """
        Returns a string representation of this URI.
        """
        if self._str is None:
            # special cases
            if self == URI.INVALID():
                self._str = "[invalid]"
            elif self == URI.EMPTY():
                self._str = ""
            elif self == URI.INLINE():
                self._str = "[inline]"
            elif self == URI.EVAL():
                self._str = "[eval]"
            elif not self._isEmpty(self._scheme) and self._isEmpty(self._host) and self._isEmpty(self._port) and self._isEmpty(self._path) and self._isEmpty(self._query):
                self._str = self._scheme + ":"
            else:
                self._str = ""
                if self._scheme in defaults.schemesWithNoDoubleSlash:
                    self._str += self._scheme + ":"
                elif self._scheme is not None:
                    self._str += self._scheme + "://"
                
                self._str += self._host
                
                if self._port is not None:
                    self._str += ":" + str(self._port)
                    
                if self._path is not None:
                    self._str += urllib.quote(self._path.encode('utf8')).decode('ascii')
                    
                if self._query is not None:
                    self._str += "?" + self._query
        return self._str
    
    def _isEmpty(self, string):
        return string is None or string == ""
    
    def _makeEmptyNone(self, string):
        if string == "":
            return None
        else:
            return string
    
    def __eq__(self, other):
        """
        Returns True if both URI objects represent the same URI (component-wise equality).
        """
        if type(other) != URI:
            return False
        return (self._scheme == other._scheme 
                and self._host == other._host 
                and self._port == other._port 
                and self._path == other._path
                and self._query == other._query
                and self._isRegularURI == other._isRegularURI)
    
    def __hash__(self):
        """
        Returns a hash value for this object that is guaranteed to be the same for two objects
        that are equal (the opposite is not necessarily true).
        """
        if self._hash is None:
            self._hash = hash(self._scheme) ^ hash(self._host) ^ hash(self._port) ^ hash(self._path) ^ hash(self._query) ^ hash(self._isRegularURI)
        return self._hash
    

class URIParser(object):
    """
    Pre-configured object that parses strings into URIs.
    """
    
    netlocRE = re.compile(r"""^((?P<user>[A-Za-z0-9`~\!#\$%^&*\(\)_+=\{\}\[\]\\\|;"<>,\./\?-]+)(:(?P<password>[A-Za-z0-9`~\!#\$%^&*\(\)_+=\{\}\[\]\\\|;"<>,\./\?-]+))?@)?(?P<host>[A-Za-z0-9._-]+)(:(?P<port>[0-9]+))?$""", re.IGNORECASE)
    
    def __init__(self, addScheme=True, defaultScheme=defaults.defaultURIScheme, addPort=False, 
                 defaultPort=defaults.defaultURIPort, schemePortMappings=defaults.schemePortMappings,
                 portSchemeMappings=defaults.portSchemeMappings, decodeEscapedCharacters=True):
        """
        Creates a new URIParser object configured with the following parameters:
        addScheme: if set to True, the scheme will be added to the URI if not present in the parsed string. If a port
                   is given, the scheme will be inferred from 'portSchemeMappings', else 'defaultScheme' will be used.
        defaultScheme: the scheme to be used if none is present in the parsed URI and if it cannot be inferred 
                       from 'portSchemeMappings'. Should be all lowercase.
        addPort: if set to True, the port will be added to the URI if not present in the parsed string. If the scheme
                 is given, the port will be inferred from 'schemePortMappings', else 'defaultPort' will be used.
        defaultPort: the port (given as a number) to be used if none is present in the parsed URI and if it cannot be
                     inferred from 'schemePortMappings'.
        schemePortMappings: a mapping from (lowercase) scheme names to port numbers.
        portSchemeMappings: a mapping from port numbers to (lowercase) scheme names.
        decodeEscapedCharacters: if set to True, %-encoded characters in the path component will be decoded after the
                                 URI has been split. This does NOT include the query parameters.
        """
        self.addScheme = addScheme
        self.defaultScheme = defaultScheme
        self.addPort = addPort
        self.defaultPort = defaultPort
        self.schemePortMappings = schemePortMappings.copy()
        self.portSchemeMappings = portSchemeMappings.copy()
        self.decodeEscapedCharacters = decodeEscapedCharacters
        self._convertPortToInt = True
        
    def _getRE(self):
        return URIParser.netlocRE
    
    def parse(self, uriString):
        """
        Parses the given 'uriString' according to the parameters set in the constructor of this URIParser and returns
        an URI object. The URI object retains only the scheme, host, port, and path components
        if they are given in 'uriString', but they may be empty or None if not in the string. This implementation is
        mostly geared toward parsing http/https URLs, but some basic parsing of URIs with the "data" and 
        "chrome-extension" schemes (and similar schemes) is possible, too.
        
        If 'uriString' consists of only whitespace or is the empty string, URI.EMPTY() will be returned. If 'uriString'
        does not represent a valid URI, URI.INVALID() will be returned.
        
        Certain components of URIs will always be removed, no matter the settings: user name and passwords before the
        host name, and fragment/anchor targets after (and including) '#'. The name of the scheme and the host will be converted
        to lowercase unless the data scheme is used (in which case the data appears as the "host"). If the entire URI
        consists of only a scheme name found in the preconfigured 'schemePortMappings' map (optionally followed by 
        : or ://), then it will be parsed as the scheme with an empty (but not None) host name.
        
        Currently not supported: unicode-to-punycode conversion of host names, and IPv6 addresses.
        """
        
        uriString = uriString.strip()
        
        # empty URI
        if uriString == "" or uriString.lower() == "null":
            return URI.EMPTY()
        
        # (known) scheme only, nothing else
        if uriString.lower() in self.schemePortMappings:
            return URI(uriString.lower(), "", None, None, None)
        elif uriString[-1:] == ":" and uriString[:-1].lower() in self.schemePortMappings:
            return URI(uriString[:-1].lower(), "", None, None, None)
        elif uriString[-3:] == "://" and uriString[:-3].lower() in self.schemePortMappings:
            return URI(uriString[:-3].lower(), "", None, None, None)
        
        res = urlparse.urlparse(uriString, allow_fragments=True)
        scheme = res.scheme.lower()
        netloc = res.netloc
        path = res.path
        query = res.query
        
        # data scheme: use data as host
        if scheme in defaults.schemesWithNoDoubleSlash:
            return URI(scheme, path, None, None, None)
        
        # urlparse behaves strangely when no scheme is present, so add http and try again
        if scheme == "" and netloc == "": # example: "www.seclab.nu"
            res = urlparse.urlparse("http://" + uriString, allow_fragments=True)
            scheme = None
            netloc = res.netloc
            path = res.path
            query = res.query
        elif scheme != "" and netloc == "": # example: www.seclab.nu:80/path
            res = urlparse.urlparse("http://" + uriString, allow_fragments=True)
            scheme = None
            netloc = res.netloc
            path = res.path
            query = res.query
        
        # split netloc part into host/port and remove user:pwd part
        netlocMatch = self._getRE().match(netloc)
        if netlocMatch is None:
            return URI.INVALID() # probably using an unsupported symbol
        host = netlocMatch.group("host").lower()
        port = netlocMatch.group("port") # number or None
        if port is not None and self._convertPortToInt:
            port = int(port)
            
        # optionally add scheme if missing
        if self.addScheme and scheme is None:
            if port is not None and port in self.portSchemeMappings:
                scheme = self.portSchemeMappings[port]
            else:
                scheme = self.defaultScheme
                
        # optionally add port if missing
        if self.addPort and port is None:
            if scheme is not None and scheme in self.schemePortMappings:
                port = self.schemePortMappings[scheme]
            else:
                port = self.defaultPort
        
        if self.decodeEscapedCharacters:
            # urllib.unquote cannot handle unicode strings
            path = urllib.unquote(path.encode("ascii")).decode("utf8")
        if path == "":
            path = None
            
        if query == "":
            query = None
            
        return URI(scheme, host, port, path, query)

