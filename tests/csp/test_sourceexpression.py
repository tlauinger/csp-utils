# -*- coding: utf-8 -*-
'''
Tests for sourceexpression.py

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''
import unittest
from csp.uri import URI
from csp.sourceexpression import SourceExpression, SelfSourceExpression, URISourceExpression, SourceExpressionParser

class SourceExpressionTest(unittest.TestCase):
    
    uri_chromeExtension = URI("chrome-extension", "mkfokfffehpeedafpekjeddnmnjhmcmk", None, None, None)
    uri_urlFull = URI("http", "seclab.nu", 80, "/path", "query")
    uri_urlFull_longer1 = URI("http", "seclab.nu", 80, "/path/1", "param=val1")
    uri_urlFull_longer2 = URI("http", "seclab.nu", 80, "/path/2", "param=val2")
    uri_urlFull_secure = URI("https", "seclab.nu", 80, "/path", "param")
    uri_urlFull_secure_defaultPort = URI("https", "seclab.nu", 443, "/path", "param")
    uri_urlFull_other = URI("other", "seclab.nu", 80, "/path", "param")
    uri_urlSubstring = URI("http", "iseclab.nu", 80, "/path", None)
    uri_url1Sub = URI("http", "blog.SecLab.nu", 80, "/path", None)
    uri_url2Sub = URI("http", "www.blog.SecLab.nu", 80, "/path", None)
    uri_empty = URI.EMPTY()
    uri_domain = URI(None, "www.seclab.nu", None, None, None)
    uri_schemedomain = URI("http", "seclab.nu", None, None, None)
    uri_schemedomain_secure = URI("https", "seclab.nu", None, None, None)
    uri_data = URI("data", "image/png;base64,iVBORw0KGgoAAAA", None, None, None)

    def test_URISourceExpression_match_star(self):
        "A source expression that should match everything (except for special URIs)."
        srcExpr = URISourceExpression(None, "*", None, None)
        selfURI = SourceExpressionTest.uri_chromeExtension
        assert srcExpr.matches(SourceExpressionTest.uri_chromeExtension, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull_secure, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull_other, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_empty, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_domain, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_data, selfURI)
        assert not srcExpr.matches(URI.EMPTY(), selfURI)
        assert not srcExpr.matches(URI.INVALID(), selfURI)
        assert not srcExpr.matches(URI.INLINE(), selfURI)
        assert not srcExpr.matches(URI.EVAL(), selfURI)
         
    def test_URISourceExpression_match_scheme_only(self):
        "A source expression where only the scheme matters"
        srcExpr = URISourceExpression("chrome-extension", None, None, None)
        selfURI = SourceExpressionTest.uri_chromeExtension
        assert srcExpr.matches(SourceExpressionTest.uri_chromeExtension, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull_secure, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull_other, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_empty, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_domain, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_data, selfURI)
         
    def test_URISourceExpression_match_nohost(self):
        "An URI with no host does not match any source expression that is not *"
        srcExpr = URISourceExpression("http", "seclab.nu", 80, None)
        selfURI = SourceExpressionTest.uri_chromeExtension
        assert not srcExpr.matches(SourceExpressionTest.uri_empty, selfURI)
         
    def test_URISourceExpression_match_scheme_different(self):
        "An URI with a different (case-insensitive) scheme than the source expression does not match."""
        srcExpr = URISourceExpression("https", "seclab.nu", 80, "/path")
        srcExprUpper = URISourceExpression("HTTPS", "seclab.nu", 80, "/path")
        selfURI = SourceExpressionTest.uri_chromeExtension
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull_secure, selfURI)
        assert not srcExprUpper.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert srcExprUpper.matches(SourceExpressionTest.uri_urlFull_secure, selfURI)
         
    def test_URISourceExpression_match_noscheme_http(self):
        """A source expression without a scheme and http as the protected resource's scheme match only
        if the URI has the scheme http or https"""
        srcExpr = URISourceExpression(None, "seclab.nu", None, None)
        selfURI = SourceExpressionTest.uri_urlFull_longer1
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull_other, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull_secure_defaultPort, selfURI)
     
    def test_URISourceExpression_match_noscheme_same(self):
        """A source expression without a scheme and the protected resource's scheme being different from http
        match only if the URI has the same scheme as the protected resource"""
        srcExpr = URISourceExpression(None, "seclab.nu", None, None)
        selfURI = SourceExpressionTest.uri_urlFull_secure
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull_other, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull_secure_defaultPort, selfURI)
         
    def test_URISourceExpression_match_scheme_star(self):
        """A source expression with a scheme and a host name including a star matches only if the domain name
        of the URI includes a subdomain at the level of the star (or below)."""
        srcExpr = URISourceExpression("http", "*.seclab.nu", None, None)
        selfURI = SourceExpressionTest.uri_urlFull_secure
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_url1Sub, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_url2Sub, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_urlSubstring, selfURI) # must be a true subdomain, not just substring
         
    def test_URISourceExpression_match_scheme_host_different(self):
        """A source expression with a scheme and a host name without a star matches only if the host name
        is the same (case insensitive)."""
        srcExpr = URISourceExpression("http", "blog.seclab.nu", None, None)
        selfURI = SourceExpressionTest.uri_urlFull_secure
        assert srcExpr.matches(SourceExpressionTest.uri_url1Sub, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_url2Sub, selfURI)
         
    def test_URISourceExpression_match_noport(self):
        """A source expression without a port matches only if the URI uses the default port for the scheme."""
        srcExpr = URISourceExpression("https", "seclab.nu", None, "/path")
        selfURI = SourceExpressionTest.uri_urlFull_secure
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull_secure, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull_secure_defaultPort, selfURI)
         
    def test_URISourceExpression_match_port_star(self):
        """A source expression matches if the port is * (and everything else matches)."""
        srcExpr = URISourceExpression("https", "seclab.nu", "*", None)
        selfURI = SourceExpressionTest.uri_urlFull_secure
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull_secure, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull_secure_defaultPort, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_schemedomain, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_schemedomain_secure, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull, selfURI)
     
    def test_URISourceExpression_match_port_same(self):
        """A source expression matches if the port is the same (and everything else matches), or
        if the port is not given in the URI, it matches the default port for the scheme."""
        srcExpr = URISourceExpression("https", "seclab.nu", 443, None)
        selfURI = SourceExpressionTest.uri_urlFull_secure
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull_secure, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull_secure_defaultPort, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_schemedomain_secure, selfURI) 
        srcExpr80 = URISourceExpression("https", "seclab.nu", 80, None)
        assert srcExpr80.matches(SourceExpressionTest.uri_urlFull_secure, selfURI)
        assert not srcExpr80.matches(SourceExpressionTest.uri_urlFull_secure_defaultPort, selfURI)
        assert not srcExpr80.matches(SourceExpressionTest.uri_schemedomain_secure, selfURI)
         
    def test_URISourceExpression_match_empty_path(self):
        """If the path component of the source expression or the URI is the empty string, it
        should be treated the same as being None."""
        srcExprEmpty = URISourceExpression("http", "seclab.nu", 80, "")
        srcExprNone = URISourceExpression("http", "seclab.nu", 80, None)
        selfURI = SourceExpressionTest.uri_urlFull_secure
        assert srcExprEmpty.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert srcExprEmpty.matches(URI("http", "seclab.nu", 80, ""), selfURI)
        assert srcExprEmpty.matches(URI("http", "seclab.nu", 80, None), selfURI)
        assert srcExprNone.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert srcExprNone.matches(URI("http", "seclab.nu", 80, ""), selfURI)
        assert srcExprNone.matches(URI("http", "seclab.nu", 80, None), selfURI)
         
    def test_URISourceExpression_match_path_slash(self):
        """If the final character of the path in the source expression is /, then the path in
        the URI must be a prefix of the path."""
        srcExprShort = URISourceExpression("http", "seclab.nu", 80, "/")
        srcExprLong = URISourceExpression("http", "seclab.nu", 80, "/path/")
        selfURI = SourceExpressionTest.uri_urlFull_secure
        assert srcExprShort.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert srcExprShort.matches(SourceExpressionTest.uri_urlFull_longer1, selfURI)
        assert srcExprShort.matches(SourceExpressionTest.uri_urlFull_longer2, selfURI)
        assert not srcExprLong.matches(SourceExpressionTest.uri_urlFull, selfURI) # this is a file
        assert srcExprLong.matches(SourceExpressionTest.uri_urlFull_longer1, selfURI)
        assert srcExprLong.matches(SourceExpressionTest.uri_urlFull_longer2, selfURI)
     
    def test_URISourceExpression_match_path_exact(self):
        """If the final character of the path in the source expression is not /, then the path
        in the URI must be an exact match (excluding the query component)."""
        srcExpr = URISourceExpression("http", "seclab.nu", 80, "/path")
        selfURI = SourceExpressionTest.uri_urlFull_secure
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull_longer1, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull_longer2, selfURI)
         
    def test_URISourceExpression_match_starhost(self):
        """Checks the behaviour of a fully specified URI with * as the hostname, that should match
        any host as long as the scheme, port, and path match (is this in line with the CSP 1.1 specification??)"""
        srcExpr = URISourceExpression("http", "*", 80, "/path")
        selfURI = SourceExpressionTest.uri_urlFull_secure
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull_longer1, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull_secure, selfURI)

    def test_URISourceExpression_match_query(self):
        """The query component in an URI should not matter when matching."""
        srcExpr = URISourceExpression("http", "seclab.nu", 80, "/path")
        selfURI = SourceExpressionTest.uri_urlFull_secure
        assert srcExpr.matches(URI("http", "seclab.nu", 80, "/path", None), selfURI)
        assert srcExpr.matches(URI("http", "seclab.nu", 80, "/path", "query"), selfURI)

    def test_SelfSourceExpression_match(self):
        """A 'self' source expression matches if the scheme, host and port of the self and other URI
        are the same (using default ports if absent)."""
        selfURI = URI("http", "seclab.nu", 80, "/other-path")
        srcExpr = SelfSourceExpression.SELF()
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull_longer1, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull_secure, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_url1Sub, selfURI)
        assert srcExpr.matches(SourceExpressionTest.uri_schemedomain, selfURI) # using default port in URI
        assert not srcExpr.matches(URI.EMPTY(), selfURI)
        assert not srcExpr.matches(URI.INVALID(), selfURI)
        assert not srcExpr.matches(URI.INLINE(), selfURI)
        assert not srcExpr.matches(URI.EVAL(), selfURI)
        selfURIDefaultPort = URI("https", "seclab.nu", None, "/yet-another-path")
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull_secure, selfURIDefaultPort)
        assert srcExpr.matches(SourceExpressionTest.uri_urlFull_secure_defaultPort, selfURIDefaultPort)
        selfURINoPort = SourceExpressionTest.uri_chromeExtension
        assert not srcExpr.matches(SourceExpressionTest.uri_chromeExtension, selfURINoPort) # no valid port can be deduced from this scheme
        
    def test_EvalInlineSourceExpression_match(self):
        """The source expressions 'unsafe-inline' and 'unsafe-eval' do not match any URI."""
        srcExprEval = SourceExpression.UNSAFE_EVAL()
        srcExprInline = SourceExpression.UNSAFE_INLINE()
        selfURI = SourceExpressionTest.uri_chromeExtension
        assert not srcExprEval.matches(SourceExpressionTest.uri_empty, selfURI)
        assert not srcExprInline.matches(SourceExpressionTest.uri_empty, selfURI)
        assert not srcExprEval.matches(URI.INVALID(), selfURI)
        assert not srcExprInline.matches(URI.INVALID(), selfURI)
        assert srcExprInline.matches(URI.INLINE(), selfURI)
        assert not srcExprInline.matches(URI.EVAL(), selfURI)
        assert not srcExprEval.matches(URI.INLINE(), selfURI)
        assert srcExprEval.matches(URI.EVAL(), selfURI)
        
    def test_InvalidSourceExpression_match(self):
        """The invalid source expression does not match anything."""
        srcExpr = SourceExpression.INVALID()
        selfURI = SourceExpressionTest.uri_chromeExtension
        assert not srcExpr.matches(SourceExpressionTest.uri_empty, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_urlFull, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_urlSubstring, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_domain, selfURI)
        assert not srcExpr.matches(SourceExpressionTest.uri_data, selfURI)
        assert not srcExpr.matches(URI.INVALID(), selfURI)
        assert not srcExpr.matches(URI.EVAL(), selfURI)
        assert not srcExpr.matches(URI.INLINE(), selfURI)
         
    def test_URISourceExpression_str(self):
        srcExprFull = URISourceExpression("http", "seclab.nu", 80, "/")
        assert str(srcExprFull) == "http://seclab.nu:80/"
        srcExprStar = URISourceExpression("http", "*.seclab.nu", None, None)
        assert str(srcExprStar) == "http://*.seclab.nu"
        srcExprScheme = URISourceExpression("chrome-extension", None, None, None)
        assert str(srcExprScheme) == "chrome-extension:"
        srcExprAll = URISourceExpression(None, "*", None, None)
        assert str(srcExprAll) == "*"
        
    def test_URISourceExpression_str_unicode(self):
        """Test URISourceExpression serialisation with unicode characters."""
        url = u'http://handbook5.com/a/a-security-analysis-of-amazon%E2%80%99s-elastic-compute-cloud-service-w14847.html'
        unicodePath = u"/a/a-security-analysis-of-amazon’s-elastic-compute-cloud-service-w14847.html"
        parsed = SourceExpressionParser().parse(url)
        assert parsed == URISourceExpression("http", "handbook5.com", None, unicodePath)
        assert str(parsed) == url # must use quoted version
    
    def test_SelfSourceExpression_str(self):
        srcExpr = SelfSourceExpression.SELF()
        assert str(srcExpr) == "'self'"
    
    def test_EvalSourceExpression_str(self):
        srcExprEval = SourceExpression.UNSAFE_EVAL()
        assert str(srcExprEval) == "'unsafe-eval'"
     
    def test_InlineSourceExpression_str(self):
        srcExprInline = SourceExpression.UNSAFE_INLINE()
        assert str(srcExprInline) == "'unsafe-inline'"
 
    def test_URISourceExpression_eq(self):
        srcExprFull1 = URISourceExpression("http", "seclab.nu", 80, "/")
        srcExprFull2 = URISourceExpression("http", "seclab.nu", 80, "/")
        assert srcExprFull1 == srcExprFull2
        assert hash(srcExprFull1) == hash(srcExprFull2)
        srcExprStar = URISourceExpression("http", "*.seclab.nu", None, None)
        assert srcExprFull1 != srcExprStar
        assert srcExprFull1 != SourceExpression.UNSAFE_EVAL()

    def test_URISourceExpression_removePath(self):
        srcExprFull = URISourceExpression("http", "seclab.nu", 80, "/path")
        assert srcExprFull.removePath() == URISourceExpression("http", "seclab.nu", 80, None)
        
    def test_URISourceExpression_schemeOnly(self):
        srcExprFull = URISourceExpression("chrome-extension", "mkfokfffehpeedafpekjeddnmnjhmcmk", None, None)
        assert srcExprFull.schemeOnly() == URISourceExpression("chrome-extension", None, None, None)
        srcExprIncomplete = URISourceExpression(None, "seclab.nu", None, None)
        assert srcExprIncomplete.schemeOnly() == SourceExpression.INVALID()

    def test_SelfSourceExpression_eq(self):
        srcExpr1 = SelfSourceExpression()
        srcExpr2 = SelfSourceExpression.SELF()
        assert srcExpr1 == srcExpr2
        assert hash(srcExpr1) == hash(srcExpr2)
        assert srcExpr1 != SourceExpression.UNSAFE_EVAL()

    def test_EvalInlineSourceExpression_eq(self):
        assert SourceExpression.UNSAFE_EVAL() == SourceExpression.UNSAFE_EVAL()
        assert hash(SourceExpression.UNSAFE_EVAL()) \
            == hash(SourceExpression.UNSAFE_EVAL())
        assert SourceExpression.UNSAFE_INLINE() == SourceExpression.UNSAFE_INLINE()
        assert hash(SourceExpression.UNSAFE_INLINE()) \
            == hash(SourceExpression.UNSAFE_INLINE())
        assert SourceExpression.UNSAFE_INLINE() != SourceExpression.UNSAFE_EVAL()
     
    def test_parse_eval(self):
        srcExpr = SourceExpressionParser().parse("'unsafe-eval'")
        assert srcExpr == SourceExpression.UNSAFE_EVAL()
        assert srcExpr.getType() == "unsafe-eval"
        assert srcExpr == SourceExpressionParser().parse("'UNSAFE-EVAL'")
 
    def test_parse_inline(self):
        srcExpr = SourceExpressionParser().parse("'unsafe-inline'")
        assert srcExpr == SourceExpression.UNSAFE_INLINE()
        assert srcExpr.getType() == "unsafe-inline"
        assert srcExpr == SourceExpressionParser().parse("'UNSAFE-INLINE'")
         
    def test_parse_self(self):
        srcExpr = SourceExpressionParser().parse("'self'")
        assert srcExpr == SelfSourceExpression.SELF()
        assert srcExpr.getType() == "self"
        assert srcExpr == SourceExpressionParser().parse("'SELF'")
        
    def test_parse_uri_full(self):
        exprStr = "http://seclab.nu:80/path"
        srcExpr = SourceExpressionParser().parse(exprStr)
        assert srcExpr == URISourceExpression("http", "seclab.nu", 80, "/path")
        assert srcExpr.getType() == "uri"
        assert srcExpr.getScheme() == "http"
        assert srcExpr.getHost() == "seclab.nu"
        assert srcExpr.getPort() == 80
        assert srcExpr.getPath() == "/path"
        assert str(srcExpr) == exprStr
         
    def test_parse_uri_scheme(self):
        exprStr = "chrome-extension:"
        srcExpr = SourceExpressionParser().parse(exprStr)
        assert srcExpr == URISourceExpression("chrome-extension", None, None, None)
        assert srcExpr.getType() == "uri"
        assert srcExpr.getScheme() == "chrome-extension"
        assert srcExpr.getHost() == None
        assert srcExpr.getPort() == None
        assert srcExpr.getPath() == None
        assert str(srcExpr) == exprStr
         
    def test_parse_uri_star(self):
        exprStr = "*"
        srcExpr = SourceExpressionParser().parse(exprStr)
        assert srcExpr == URISourceExpression(None, "*", None, None)
         
    def test_parse_uri_noscheme(self):
        exprStr = "seclab.nu"
        srcExpr = SourceExpressionParser().parse(exprStr)
        assert srcExpr == URISourceExpression(None, "seclab.nu", None, None)
         
    def test_parse_uri_noscheme_path(self):
        exprStr = "seclab.nu/blah"
        srcExpr = SourceExpressionParser().parse(exprStr)
        assert srcExpr == URISourceExpression(None, "seclab.nu", None, "/blah")
         
    def test_parse_uri_noscheme_port(self):
        exprStr = "seclab.nu:443"
        srcExpr = SourceExpressionParser().parse(exprStr)
        assert srcExpr == URISourceExpression(None, "seclab.nu", 443, None)
         
    def test_parse_uri_noscheme_port_path(self):
        exprStr = "seclab.nu:443/blah"
        srcExpr = SourceExpressionParser().parse(exprStr)
        assert srcExpr == URISourceExpression(None, "seclab.nu", 443, "/blah")
         
    def test_parse_uri_starsubdomain(self):
        exprStr = "http://*.seclab.nu"
        srcExpr = SourceExpressionParser().parse(exprStr)
        assert srcExpr == URISourceExpression("http", "*.seclab.nu", None, None)
         
    def test_parse_uri_nopath(self):
        exprStr = "http://localhost:8080"
        srcExpr = SourceExpressionParser().parse(exprStr)
        assert srcExpr == URISourceExpression("http", "localhost", 8080, None)
         
    def test_parse_uri_noport(self):
        exprStr = "https://seclab.nu/"
        srcExpr = SourceExpressionParser().parse(exprStr)
        assert srcExpr == URISourceExpression("https", "seclab.nu", None, "/")
         
    def test_parse_uri_scheme_star_port_path(self):
        exprStr = "http://*:80/path"
        srcExpr = SourceExpressionParser(knownSchemes=('blubb', 'http')).parse(exprStr)
        assert srcExpr == URISourceExpression("http", "*", 80, "/path")
        
    def test_parse_uri_scheme_starport(self):
        exprStr = "http://host:*/path"
        srcExpr = SourceExpressionParser().parse(exprStr)
        assert srcExpr == URISourceExpression("http", "host", "*", "/path")

    def test_parse_uri_decoding(self):
        exprStr = "http://domain/path%20space"
        srcExpr = SourceExpressionParser().parse(exprStr)
        assert srcExpr == URISourceExpression("http", "domain", None, "/path space")
        
    def test_parse_unsupported_scheme_fails(self):
        exprStr = "my-scheme://domain/path"
        srcExpr = SourceExpressionParser(knownSchemes=('http', 'https')).parse(exprStr)
        assert srcExpr == SourceExpression.INVALID()


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.test_uri']
    unittest.main()
