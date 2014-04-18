# -*- coding: utf-8 -*-
'''
Tests for uri.py

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''
import unittest
from csp.uri import URI, URIParser

class URITest(unittest.TestCase):

    def test_default_full_URI(self):
        """Simple test with default parameters, splitting a fully specified URI."""
        uriString = "http://www.seclab.nu:80/path/a?param=true"
        uriExpected = URI("http", "www.seclab.nu", 80, "/path/a", "param=true")
        assert URIParser().parse(uriString) == uriExpected
         
    def test_no_modification_partial_URI_data(self):
        """Data URIs use only the scheme and the host for the data. The data should not be converted to
        lowercase."""
        uriString = "data:image/png;base64,iVBORw0KGgoAAAA"
        uriExpected = URI("data", "image/png;base64,iVBORw0KGgoAAAA", None, None)
        assert URIParser().parse(uriString) == uriExpected
        
    def test_no_modification_partial_URI_about(self):
        """about: URIs are similar to data URIs."""
        uriString = "about:blank"
        uriExpected = URI("about", "blank", None, None)
        assert URIParser().parse(uriString) == uriExpected
        
    def test_no_modification_partial_URI_viewSource(self):
        """view-source: URIs are similar to data URIs."""
        uriString = "view-source:http://www.seclab.nu/page/"
        uriExpected = URI("view-source", "http://www.seclab.nu/page/", None, None)
        assert URIParser().parse(uriString) == uriExpected
         
    def test_no_modification_partial_URI_host(self):
        """Simple test with no modification and only host in URI."""
        uriString = "www.seclab.nu"
        uriExpected = URI(None, "www.seclab.nu", None, None)
        assert URIParser(addScheme=False, addPort=False).parse(uriString) == uriExpected
        
    def test_no_modification_partial_URI_host_query(self):
        """Simple test with no modification and only host and query in URI."""
        uriString = "www.seclab.nu?query"
        uriExpected = URI(None, "www.seclab.nu", None, None, "query")
        assert URIParser(addScheme=False, addPort=False).parse(uriString) == uriExpected
        
    def test_no_modification_partial_URI_host_port(self):
        """Simple test with no modification and only host and port in URI."""
        uriString = "www.seclab.nu:80"
        uriExpected = URI(None, "www.seclab.nu", 80, None)
        assert URIParser(addScheme=False, addPort=False).parse(uriString) == uriExpected
        
    def test_no_modification_partial_URI_host_port_query(self):
        """Simple test with no modification and only host and port and query in URI."""
        uriString = "www.seclab.nu:80?query"
        uriExpected = URI(None, "www.seclab.nu", 80, None, "query")
        assert URIParser(addScheme=False, addPort=False).parse(uriString) == uriExpected
         
    def test_no_modification_partial_URI_data_scheme(self):
        """Ensure that an URI with only 'data' is parsed as the scheme with empty host name, not as host name."""
        uriString = "data"
        uriExpected = URI("data", "", None, None)
        assert URIParser(addScheme=False, addPort=False).parse(uriString) == uriExpected
         
    def test_no_modification_partial_URI_data_scheme_colon(self):
        """Ensure that an URI with only 'data' is parsed as the scheme with empty host name, not as host name."""
        uriString = "data:"
        uriExpected = URI("data", "", None, None)
        assert URIParser(addScheme=True, addPort=True).parse(uriString) == uriExpected 
         
    def test_no_modification_partial_URI_data_scheme_colon_slash_slash(self):
        """Ensure that an URI with only 'data' is parsed as the scheme with empty host name, not as host name."""
        uriString = "data://"
        uriExpected = URI("data", "", None, None)
        assert URIParser().parse(uriString) == uriExpected
     
    def test_empty_URI(self):
        """Ensure that URI.EMPTY is returned when a string with only whitespace is parsed."""
        uriString = " "
        uriExpected = URI.EMPTY()
        assert URIParser().parse(uriString) == uriExpected
         
    def test_invalid_URI(self):
        """Ensure that URI.INVALID is returned when an invalid URI is parsed."""
        uriString = "http://blah:blubb:baeh?"
        uriExpected = URI.INVALID()
        actual = URIParser().parse(uriString)
        assert actual == uriExpected
     
    def test_no_modification_partial_URI_host_path(self):
        """Simple test with no modification, splitting a partially specified URI."""
        uriString = "www.seclab.nu/path/file"
        uriExpected = URI(None, "www.seclab.nu", None, "/path/file")
        actual = URIParser(addScheme=False, addPort=False, decodeEscapedCharacters=False) \
            .parse(uriString)
        assert actual == uriExpected
        
    def test_no_modification_partial_URI_host_path_query(self):
        """Simple test with no modification, splitting a partially specified URI."""
        uriString = "www.seclab.nu/path/file?query"
        uriExpected = URI(None, "www.seclab.nu", None, "/path/file", "query")
        actual = URIParser(addScheme=False, addPort=False, decodeEscapedCharacters=False) \
            .parse(uriString)
        assert actual == uriExpected
         
    def test_addScheme_partial_URI_host_path(self):
        """Test if scheme is added properly to partially specified URI."""
        uriString = "www.seclab.nu/path/file"
        uriExpected = URI("test-scheme", "www.seclab.nu", None, "/path/file")
        assert URIParser(addScheme=True, defaultScheme="test-scheme", addPort=False, decodeEscapedCharacters=False) \
            .parse(uriString) == uriExpected
             
    def test_addScheme_addPort_defaultScheme_defaultPort_partial_URI_host_path(self):
        """Test if scheme and port are added properly to partially specified URI."""
        uriString = "www.seclab.nu/path/file"
        uriExpected = URI("test-scheme", "www.seclab.nu", 42, "/path/file")
        assert URIParser(addScheme=True, defaultScheme="test-scheme", addPort=True, defaultPort=42, decodeEscapedCharacters=False) \
            .parse(uriString) == uriExpected
             
    def test_addScheme_addPort_defaultScheme_schemePortMappings_partial_URI_host_path(self):
        """Test if scheme and port are added properly to partially specified URI."""
        uriString = "www.seclab.nu/path/file"
        uriExpected = URI("test-scheme", "www.seclab.nu", 333, "/path/file")
        assert URIParser(addScheme=True, defaultScheme="test-scheme", addPort=True, schemePortMappings={"test-scheme": 333}, decodeEscapedCharacters=False) \
            .parse(uriString) == uriExpected
             
    def test_addPort_defaultPort_partial_URI_host_path(self):
        """Test if scheme and port are added properly to partially specified URI."""
        uriString = "www.seclab.nu/path/file"
        uriExpected = URI(None, "www.seclab.nu", 2424, "/path/file")
        assert URIParser(addScheme=False, defaultScheme="test-scheme", addPort=True, defaultPort=2424, schemePortMappings={"test-scheme": 333}, portSchemeMappings={2424: "test-scheme"}, decodeEscapedCharacters=False) \
            .parse(uriString) == uriExpected
         
    def test_no_modification_partial_URI_scheme_host_path(self):
        """Simple test with no modification, splitting a partially specified URI."""
        uriString = "https://www.seclab.nu/path/file"
        uriExpected = URI("https", "www.seclab.nu", None, "/path/file")
        assert URIParser(addScheme=False, addPort=False, decodeEscapedCharacters=False) \
            .parse(uriString) == uriExpected
            
    def test_no_modification_partial_URI_scheme_host_path_query(self):
        """Simple test with no modification, splitting a partially specified URI."""
        uriString = "https://www.seclab.nu/path/file?query=here"
        uriExpected = URI("https", "www.seclab.nu", None, "/path/file", "query=here")
        assert URIParser(addScheme=False, addPort=False, decodeEscapedCharacters=False) \
            .parse(uriString) == uriExpected
             
    def test_addPort_schemePortMappings_partial_URI_scheme_host_path(self):
        """Simple test with inferring the port from scheme and scheme->port mapping, splitting a partially specified URI."""
        uriString = "https://www.seclab.nu/path/file"
        uriExpected = URI("https", "www.seclab.nu", 123, "/path/file")
        assert URIParser(addScheme=False, addPort=True, defaultPort=456, schemePortMappings={'https': 123}, decodeEscapedCharacters=False) \
            .parse(uriString) == uriExpected
             
    def test_addPort_defaultPort_partial_URI_scheme_host_path(self):
        """Simple test with adding the default port, splitting a partially specified URI."""
        uriString = "https://www.seclab.nu/path/file"
        uriExpected = URI("https", "www.seclab.nu", 123, "/path/file")
        assert URIParser(addScheme=False, addPort=True, defaultPort=123, schemePortMappings={'http': 456}, decodeEscapedCharacters=False) \
            .parse(uriString) == uriExpected
         
    def test_no_modification_partial_URI_host_port_path(self):
        """Simple test with no modification, splitting a partially specified URI."""
        uriString = "www.seclab.nu:8080/path/file"
        uriExpected = URI(None, "www.seclab.nu", 8080, "/path/file")
        actual = URIParser(addScheme=False, addPort=False, decodeEscapedCharacters=False) \
                .parse(uriString)
        assert actual == uriExpected
        
    def test_no_modification_partial_URI_host_port_path_query(self):
        """Simple test with no modification, splitting a partially specified URI."""
        uriString = "www.seclab.nu:8080/path/file?query"
        uriExpected = URI(None, "www.seclab.nu", 8080, "/path/file", "query")
        actual = URIParser(addScheme=False, addPort=False, decodeEscapedCharacters=False) \
                .parse(uriString)
        assert actual == uriExpected
                 
    def test_addScheme_defaultScheme_partial_URI_host_port_path(self):
        """Simple test with adding the default scheme, splitting a partially specified URI."""
        uriString = "www.seclab.nu:8080/path/file"
        uriExpected = URI("http", "www.seclab.nu", 8080, "/path/file")
        assert URIParser(addScheme=True, defaultScheme="http", portSchemeMappings={80: "http"}, addPort=True, decodeEscapedCharacters=False) \
                .parse(uriString) == uriExpected
                 
    def test_addScheme_portSchemeMappings_partial_URI_host_port_path(self):
        """Simple test with inferring the scheme from the port and port->scheme mapping, splitting a partially specified URI."""
        uriString = "www.seclab.nu:8080/path/file"
        uriExpected = URI("http", "www.seclab.nu", 8080, "/path/file")
        assert URIParser(addScheme=True, defaultScheme="https", portSchemeMappings={80: 'http', 8080: 'http'}, addPort=True, decodeEscapedCharacters=False) \
                .parse(uriString) == uriExpected
         
    def test_no_modification_partial_URI_scheme_host(self):
        """Simple test with no modification, splitting a partially specified URI."""
        uriString = "chrome-extension://mkfokfffehpeedafpekjeddnmnjhmcmk"
        uriExpected = URI("chrome-extension", "mkfokfffehpeedafpekjeddnmnjhmcmk", None, None)
        assert URIParser(addScheme=False, addPort=False, decodeEscapedCharacters=False) \
                .parse(uriString) == uriExpected
         
    def test_addPort_schemePortMappingsNone_partial_URI_scheme_host(self):
        """Simple test with "adding" a None port, splitting a partially specified URI."""
        uriString = "chrome-extension://mkfokfffehpeedafpekjeddnmnjhmcmk"
        uriExpected = URI("chrome-extension", "mkfokfffehpeedafpekjeddnmnjhmcmk", None, None)
        assert URIParser(addScheme=True, addPort=True, defaultPort=123, schemePortMappings={'chrome-extension': None}, decodeEscapedCharacters=False) \
            .parse(uriString) == uriExpected
             
    def test_stripAnchor_full_URI(self):
        """Check if anchor part properly removed."""
        uriString = "http://www.seclab.nu:80/index.php?parameter=value&more#anchor"
        uriExpected = URI("http", "www.seclab.nu", 80, "/index.php", "parameter=value&more")
        actual = URIParser(decodeEscapedCharacters=False) \
            .parse(uriString)
        assert actual == uriExpected
             
    def test_stripUserPassword_full_URI(self):
        """Check if user:password part properly removed."""
        uriString = "http://user:password@www.seclab.nu:80/index.php"
        uriExpected = URI("http", "www.seclab.nu", 80, "/index.php")
        assert URIParser(decodeEscapedCharacters=False) \
            .parse(uriString) == uriExpected
            
    def test_stripUserPassword_full_URI_IPv4(self):
        """Check if user:password part properly removed (with IPv4 address)."""
        uriString = "http://user:password@123.123.123.123:80/index.php"
        uriExpected = URI("http", "123.123.123.123", 80, "/index.php")
        assert URIParser(decodeEscapedCharacters=False) \
            .parse(uriString) == uriExpected
             
    def test_stripUserPassword_userOnly_URI(self):
        """Check if user:password part properly removed."""
        uriString = "http://user@www.seclab.nu:80/index.php"
        uriExpected = URI("http", "www.seclab.nu", 80, "/index.php")
        actual = URIParser(decodeEscapedCharacters=False) \
            .parse(uriString)
        assert actual == uriExpected
        
    def test_stripUserPassword_userOnly_URI_IPv4(self):
        """Check if user:password part properly removed (with IPv4 address)."""
        uriString = "http://user@123.123.123.123:80/index.php"
        uriExpected = URI("http", "123.123.123.123", 80, "/index.php")
        actual = URIParser(decodeEscapedCharacters=False) \
            .parse(uriString)
        assert actual == uriExpected
             
    def test_decodeEscapedCharacters_full_URI(self):
        """Check if escaped characters in the path are correctly decoded."""
        uriString = "http://www.seclab.nu:80/a%20path/index.py?math=3%3D%281%2B1%29%2A1.5"
        uriExpected = URI("http", "www.seclab.nu", 80, "/a path/index.py", "math=3%3D%281%2B1%29%2A1.5")
        actual = URIParser(decodeEscapedCharacters=True) \
            .parse(uriString)
        assert actual == uriExpected
             
    def test_lowercase(self):
        """Checks that the scheme and host name are converted to lower case when parsing."""
        uriString = "Http://www.SecLab.nu/"
        uriExpected = URI("http", "www.seclab.nu", 80, "/")
        assert URIParser(addPort=True, schemePortMappings={'http': 80}) \
                .parse(uriString) == uriExpected
                
    def test_underscore(self):
        """Checks that underscores in subdomains are parsed correctly."""
        uriString = "https://i_simwebjs_info.tlscdn.com/sweb/javascript.js"
        uriExpected = URI("https", "i_simwebjs_info.tlscdn.com", None, "/sweb/javascript.js")
        assert URIParser(addPort=False).parse(uriString) == uriExpected
            
    def test_remove_path(self):
        """Checks that the path and query are properly removed from a URI object."""
        inputURI = URI("https", "seclab.nu", 443, "/index.html", "query=value")
        expectedURI = URI("https", "seclab.nu", 443, None, None)
        assert inputURI.removePath() == expectedURI
        assert URI.INVALID().removePath() == URI.INVALID()
        
    def test_getters(self):
        """Checks the getters of URI."""
        inputURI = URI("https", "seclab.nu", 443, "/index.html", "param=val")
        assert inputURI.getScheme() == "https"
        assert inputURI.getHost() == "seclab.nu"
        assert inputURI.getPort() == 443
        assert inputURI.getPath() == "/index.html"
        assert inputURI.getQuery() == "param=val"
        assert inputURI.isRegularURI() == True
        
    def test_regularURI_singletons(self):
        """All the singleton URIs should return False for isRegularURI()."""
        assert URI.EMPTY().isRegularURI() == False
        assert URI.INVALID().isRegularURI() == False
        assert URI.INLINE().isRegularURI() == False
        assert URI.EVAL().isRegularURI() == False
        assert URI("http", "seclab.nu", None, None, None).isRegularURI() == True
        
    def test_str(self):
        """Checks the string serialisation of a few URIs."""
        assert str(URI("data", "", None, None)) == "data:"
        assert str(URI("data", "image/png;base64,iVBORw0KGgoAAAA", None, None)) == "data:image/png;base64,iVBORw0KGgoAAAA"
        assert str(URI("about", "blank", None, None)) == "about:blank"
        assert str(URI("http", "www.seclab.org", 80, "/file", "parameter=value")) == "http://www.seclab.org:80/file?parameter=value"
        assert str(URI(None, "www.seclab.nu", None, None)) == "www.seclab.nu"
        assert str(URI.EMPTY()) == ""
        assert str(URI.INVALID()) == "[invalid]"
        assert str(URI.INLINE()) == "[inline]"
        assert str(URI.EVAL()) == "[eval]"
        
    def test_str_unicode(self):
        """Test URI serialisation with unicode characters."""
        url = u'http://handbook5.com/a/a-security-analysis-of-amazon%E2%80%99s-elastic-compute-cloud-service-w14847.html'
        unicodePath = u"/a/a-security-analysis-of-amazon’s-elastic-compute-cloud-service-w14847.html"
        parsed = URIParser(decodeEscapedCharacters=True).parse(url)
        assert parsed == URI("http", "handbook5.com", None, unicodePath)
        assert str(parsed) == url # must use quoted version
        
    def test_eq(self):
        """Checks that the eq and hash methods are consistent for a few URIs."""
        uri1a = URI("http", "www.seclab.org", 80, "/", "query")
        uri1b = URI("http", "www.seclab.org", 80, "/", "query")
        uri2 = URI("https", "www.seclab.org", 80, "/")
        uri3 = URI("http", "www.seclab.org", 80, None)
        assert uri1a == uri1b
        assert hash(uri1a) == hash(uri1b)
        assert uri1a != uri2
        assert uri1a != uri3
        assert uri2 != uri3
        assert URI.EMPTY() == URI.EMPTY()
        assert URI.INVALID() == URI.INVALID()
        assert URI.EMPTY() not in (uri1a, uri1b, uri2, uri3, URI.INVALID(), 
                                       URI.INLINE(), URI.EVAL())
        assert URI.INVALID() not in (uri1a, uri1b, uri2, uri3, URI.EMPTY(),
                                         URI.INLINE(), URI.EVAL())
        assert URI.INLINE() not in (uri1a, uri1b, uri2, uri3, URI.EMPTY(),
                                         URI.INVALID(), URI.EVAL())
        assert URI.EVAL() not in (uri1a, uri1b, uri2, uri3, URI.EMPTY(),
                                         URI.INVALID(), URI.INLINE())
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.test_uri']
    unittest.main()
