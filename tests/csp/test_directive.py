'''
Tests for directive.py

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''

import unittest
from csp.directive import Directive, DirectiveParser
from csp.uri import URI
from csp.sourceexpression import SelfSourceExpression, URISourceExpression, SourceExpression


class DirectiveTest(unittest.TestCase):
    
    sampleURI1 = URI("http", "seclab.nu", 80, None, None)
    sampleURI2 = URI("http", "seclab.ccs.neu.edu", 80, "/path", "query-parameters")
    sampleSrcExpr1a = URISourceExpression("http", "seclab.nu", "*", None)
    sampleSrcExpr1b = URISourceExpression("http", "seclab.nu", "*", None)
    sampleSrcExpr2 = URISourceExpression("https", "seclab.nu", 443, "/path1")
    sampleSrcExpr3 = URISourceExpression("https", "seclab.nu", 443, "/path2")
    
    def testDirective_str_none(self):
        assert str(Directive("script-src", [])) == "script-src 'none'"
    
    def testDirective_str_regular(self):
        srcExpr1 = URISourceExpression("http", "seclab.nu", "*", None)
        srcExpr2 = SourceExpression.UNSAFE_INLINE()
        srcExpr3 = SelfSourceExpression.SELF()
        assert str(Directive("style-src", [srcExpr1, srcExpr2, srcExpr3])) \
            == "style-src 'self' 'unsafe-inline' http://seclab.nu:*"
            
    def testDirective_str_invalid(self):
        assert str(Directive.INVALID()) == "[invalid]"
        
    def testDirective_str_inlineStyleBaseRestriction(self):
        assert str(Directive.INLINE_STYLE_BASE_RESTRICTION()) == "inline style base restriction"
        
    def testDirective_str_inlineScriptBaseRestriction(self):
        assert str(Directive.INLINE_SCRIPT_BASE_RESTRICTION()) == "inline script base restriction"
        
    def testDirective_str_evalScriptBaseRestriction(self):
        assert str(Directive.EVAL_SCRIPT_BASE_RESTRICTION()) == "eval script base restriction"

    def testDirective_getType(self):
        assert Directive("default-src", []).getType() == "default-src"
        assert Directive.INLINE_STYLE_BASE_RESTRICTION().getType() == "style-src"
        assert Directive.INLINE_SCRIPT_BASE_RESTRICTION().getType() == "script-src"
        assert Directive.EVAL_SCRIPT_BASE_RESTRICTION().getType() == "script-src"
        
    def testDirective_init_removeDoubleExpressions(self):
        srcExpr1 = URISourceExpression("http", "seclab.nu", "*", None)
        srcExpr2 = URISourceExpression("http", "seclab.nu", "*", None)
        directive = Directive("style-src", [srcExpr1, srcExpr2])
        whitelisted = directive.getWhitelistedSourceExpressions()
        assert whitelisted == set([srcExpr1]) # duplicate source expressions should be removed
        assert whitelisted == set([srcExpr2]) # sets should be equal
        assert directive == Directive("style-src", [srcExpr1])
        assert directive == Directive("style-src", [srcExpr2])
            
    def testDirective_init_removeDoubleSelfExpressions(self):
        srcExpr1 = URISourceExpression("http", "seclab.nu", "*", None)
        srcExpr2 = SelfSourceExpression.SELF()
        srcExpr3 = SelfSourceExpression()
        whitelisted = Directive("img-src", [srcExpr1, srcExpr2, srcExpr3]).getWhitelistedSourceExpressions()
        assert len(whitelisted) == 2 # one self expression should be removed (can have at most one)
        assert srcExpr1 in whitelisted and (srcExpr2 in whitelisted or srcExpr3 in whitelisted)
    
    def testDirective_init_removeInvalidSourceExpressions(self):
        assert Directive("img-src", [SourceExpression.INVALID()]) == Directive("img-src", [])
        
    def testDirective_eq(self):
        srcExpr1 = URISourceExpression("http", "seclab.nu", "*", None)
        srcExpr2 = URISourceExpression("https", "seclab.nu", 443, "/")
        directive1a = Directive("object-src", [srcExpr1, srcExpr2])
        directive1b = Directive("object-src", [srcExpr2, srcExpr1])
        directive2 = Directive("frame-src", [srcExpr1, srcExpr2])
        directive3 = Directive("object-src", [srcExpr2])
        directive4a = Directive("script-src", (SourceExpression.UNSAFE_INLINE(),))
        directive4b = Directive("script-src", (SourceExpression("unsafe-inline"),))
        assert directive1a == directive1b
        assert hash(directive1a) == hash(directive1b)
        assert directive1a != directive2
        assert directive1a != directive3
        assert directive2 != directive3
        assert directive4a == directive4b
        assert hash(directive4a) == hash(directive4b)
        assert Directive.INVALID() == Directive.INVALID()
        assert Directive.INVALID() not in (directive1a, directive1b, directive2, directive3)
        assert Directive.INLINE_STYLE_BASE_RESTRICTION() not in (directive1a, directive1b, directive2, directive3)
        
    def testDirective_matches_special(self):
        """An invalid/special directive matches nothing."""
        selfURI = DirectiveTest.sampleURI2
        assert not Directive.INVALID().matches(URI.EMPTY(), selfURI)
        assert not Directive.INVALID().matches(URI.INVALID(), selfURI)
        assert not Directive.INVALID().matches(URI.INLINE(), selfURI)
        assert not Directive.INVALID().matches(URI.EVAL(), selfURI)
        assert not Directive.INVALID().matches(DirectiveTest.sampleURI1, selfURI)
        assert not Directive.EVAL_SCRIPT_BASE_RESTRICTION().matches(URI.EMPTY(), selfURI)
        assert not Directive.EVAL_SCRIPT_BASE_RESTRICTION().matches(URI.INVALID(), selfURI)
        assert not Directive.EVAL_SCRIPT_BASE_RESTRICTION().matches(URI.INLINE(), selfURI)
        assert not Directive.EVAL_SCRIPT_BASE_RESTRICTION().matches(URI.EVAL(), selfURI)
        assert not Directive.EVAL_SCRIPT_BASE_RESTRICTION().matches(DirectiveTest.sampleURI1, selfURI)
        assert not Directive.INLINE_SCRIPT_BASE_RESTRICTION().matches(URI.EMPTY(), selfURI)
        assert not Directive.INLINE_SCRIPT_BASE_RESTRICTION().matches(URI.INVALID(), selfURI)
        assert not Directive.INLINE_SCRIPT_BASE_RESTRICTION().matches(URI.INLINE(), selfURI)
        assert not Directive.INLINE_SCRIPT_BASE_RESTRICTION().matches(URI.EVAL(), selfURI)
        assert not Directive.INLINE_SCRIPT_BASE_RESTRICTION().matches(DirectiveTest.sampleURI1, selfURI)
        assert not Directive.INLINE_STYLE_BASE_RESTRICTION().matches(URI.EMPTY(), selfURI)
        assert not Directive.INLINE_STYLE_BASE_RESTRICTION().matches(URI.INVALID(), selfURI)
        assert not Directive.INLINE_STYLE_BASE_RESTRICTION().matches(URI.INLINE(), selfURI)
        assert not Directive.INLINE_STYLE_BASE_RESTRICTION().matches(URI.EVAL(), selfURI)
        assert not Directive.INLINE_STYLE_BASE_RESTRICTION().matches(DirectiveTest.sampleURI1, selfURI)
        
    def testDirective_matches(self):
        """A few standard tests."""
        directive1 = Directive("object-src", [DirectiveTest.sampleSrcExpr1a, DirectiveTest.sampleSrcExpr2])
        directive2 = Directive("frame-src", [DirectiveTest.sampleSrcExpr2])
        directive3 = Directive("default-src", [])
        selfURI = DirectiveTest.sampleURI2
        assert directive1.matches(DirectiveTest.sampleURI1, selfURI)
        assert not directive1.matches(DirectiveTest.sampleURI2, selfURI)
        assert not directive2.matches(DirectiveTest.sampleURI1, selfURI)
        assert not directive2.matches(DirectiveTest.sampleURI2, selfURI)
        assert not directive3.matches(DirectiveTest.sampleURI1, selfURI)
        assert not directive3.matches(DirectiveTest.sampleURI2, selfURI)
        
    def testDirective_generateDirective_regular(self):
        violated = Directive("object-src", [DirectiveTest.sampleSrcExpr1a, DirectiveTest.sampleSrcExpr2])
        generated = violated.generateDirective("regular", DirectiveTest.sampleURI2)
        assert generated == Directive("object-src", [URISourceExpression("http", "seclab.ccs.neu.edu", 80, "/path")])
    
    def testDirective_generateDirective_inline(self):
        violated = Directive("style-src", [DirectiveTest.sampleSrcExpr2])
        generated = violated.generateDirective("inline", URI.EMPTY())
        assert generated == Directive("style-src", [SourceExpression.UNSAFE_INLINE()])
        
    def testDirective_generateDirective_inline_special_style(self):
        violated = Directive.INLINE_STYLE_BASE_RESTRICTION()
        generated = violated.generateDirective("inline", DirectiveTest.sampleURI1)
        assert generated == Directive("style-src", [SourceExpression.UNSAFE_INLINE()])
        
    def testDirective_generateDirective_inline_special_script(self):
        violated = Directive.INLINE_SCRIPT_BASE_RESTRICTION()
        generated = violated.generateDirective("inline", DirectiveTest.sampleURI1)
        assert generated == Directive("script-src", [SourceExpression.UNSAFE_INLINE()])
        
    def testDirective_generateDirective_eval(self):
        violated = Directive("script-src", [DirectiveTest.sampleSrcExpr1a])
        generated = violated.generateDirective("eval", URI.EMPTY())
        assert generated == Directive("script-src", [SourceExpression.UNSAFE_EVAL()])
        
    def testDirective_generateDirective_eval_special(self):
        violated = Directive.EVAL_SCRIPT_BASE_RESTRICTION()
        generated = violated.generateDirective("eval", DirectiveTest.sampleURI2)
        assert generated == Directive("script-src", [SourceExpression.UNSAFE_EVAL()])
        
    def testDirective_generateDirective_invalidType(self):
        violated = Directive("script-src", [DirectiveTest.sampleSrcExpr1a])
        assert violated.generateDirective("evaluate", URI.EMPTY()) == Directive.INVALID()
        
    def testDirective_generateDirective_invalidDirective(self):
        assert Directive.INVALID().generateDirective("eval", URI.EMPTY()) == Directive.INVALID()
        
    def testDirective_generateDirective_defaultSrcNotAllowed(self):
        violated = Directive("default-src", [])
        assert violated.generateDirective("regular", DirectiveTest.sampleURI1) == Directive.INVALID()
        
    def testDirective_generateDirective_incompatibleType(self):
        violatedWrongInlineType = Directive("object-src", [])
        violatedWrongEvalType = Directive("style-src", [])
        assert violatedWrongInlineType.generateDirective("inline", DirectiveTest.sampleURI1) == Directive.INVALID()
        assert violatedWrongEvalType.generateDirective("eval", DirectiveTest.sampleURI1) == Directive.INVALID()
        
    def testDirective_generateDirective_incompatibleURI(self):
        violatedRegular = Directive("object-src", [])
        violatedInline = Directive("style-src", [])
        violatedEval = Directive("script-src", [])
        assert violatedRegular.generateDirective("regular", URI.EMPTY()) == Directive.INVALID()
        assert violatedRegular.generateDirective("regular", URI.INVALID()) == Directive.INVALID()
        #assert violatedInline.generateDirective("inline", DirectiveTest.sampleURI1) == Directive.INVALID()
        assert violatedInline.generateDirective("inline", URI.INVALID()) == Directive.INVALID()
        #assert violatedEval.generateDirective("eval", DirectiveTest.sampleURI1) == Directive.INVALID()
        assert violatedEval.generateDirective("eval", URI.INVALID()) == Directive.INVALID()
    
    def testDirective_isRegularDirective(self):
        assert Directive.INVALID().isRegularDirective() == False
        assert Directive.EVAL_SCRIPT_BASE_RESTRICTION().isRegularDirective() == False
        assert Directive.INLINE_SCRIPT_BASE_RESTRICTION().isRegularDirective() == False
        assert Directive.INLINE_STYLE_BASE_RESTRICTION().isRegularDirective() == False
        assert Directive("default-src", []).isRegularDirective() == True
    
    def testDirective_combine_regular(self):
        direct1 = Directive("default-src", [DirectiveTest.sampleSrcExpr1a])
        direct2 = Directive("default-src", [DirectiveTest.sampleSrcExpr2])
        expected = Directive("default-src", [DirectiveTest.sampleSrcExpr1a, DirectiveTest.sampleSrcExpr2])
        assert direct1.combinedDirective(direct2) == expected
        assert direct2.combinedDirective(direct1) == expected
        assert direct1.combinedDirective(direct1) == direct1
        assert direct2.combinedDirective(direct2) == direct2
        
    def testDirective_combine_differentType(self):
        direct1 = Directive("default-src", [DirectiveTest.sampleSrcExpr1a])
        direct2 = Directive("script-src", [DirectiveTest.sampleSrcExpr2])
        assert direct1.combinedDirective(direct2) == Directive.INVALID()
        assert direct2.combinedDirective(direct1) == Directive.INVALID()
        
    def testDirective_combine_notRegularURI(self):
        direct = Directive("style-src", [SelfSourceExpression.SELF()])
        assert direct.combinedDirective(Directive.INVALID()) == Directive.INVALID()
        assert Directive.INVALID().combinedDirective(direct) == Directive.INVALID()
        assert direct.combinedDirective(Directive.EVAL_SCRIPT_BASE_RESTRICTION()) == Directive.INVALID()
        assert Directive.EVAL_SCRIPT_BASE_RESTRICTION().combinedDirective(direct) == Directive.INVALID()
        
    def testDirective_combine_removeDuplicates(self):
        direct1 = Directive("img-src", [DirectiveTest.sampleSrcExpr1a, SelfSourceExpression.SELF()])
        direct2 = Directive("img-src", [DirectiveTest.sampleSrcExpr1b])
        assert direct1.combinedDirective(direct2) == direct1
        assert direct2.combinedDirective(direct1) == direct1
    
    def testDirective_withoutPaths(self):
        withPaths = Directive("script-src", [DirectiveTest.sampleSrcExpr2, SelfSourceExpression.SELF()])
        withoutPaths = Directive("script-src", [DirectiveTest.sampleSrcExpr2.removePath(), SelfSourceExpression.SELF()])
        assert withPaths.withoutPaths() == withoutPaths
        assert withoutPaths.withoutPaths() == withoutPaths
        assert Directive.INVALID().withoutPaths() == Directive.INVALID()
        assert Directive.EVAL_SCRIPT_BASE_RESTRICTION().withoutPaths() == Directive.EVAL_SCRIPT_BASE_RESTRICTION()
        assert Directive.INLINE_SCRIPT_BASE_RESTRICTION().withoutPaths() == Directive.INLINE_SCRIPT_BASE_RESTRICTION()
        assert Directive.INLINE_STYLE_BASE_RESTRICTION().withoutPaths() == Directive.INLINE_STYLE_BASE_RESTRICTION()
        
    def testDirective_withoutPaths_schemeOnly(self):
        chromeExt = Directive("img-src", [URISourceExpression("chrome-extension", "mkfokfffehpeedafpekjeddnmnjhmcmk", None, None)])
        assert chromeExt.withoutPaths(["chrome-extension"]) == Directive("img-src", [URISourceExpression("chrome-extension", None, None, None)])
        
    def testDirective_withoutPaths_removeDuplicates(self):
        withPaths = Directive("script-src", [DirectiveTest.sampleSrcExpr2, DirectiveTest.sampleSrcExpr3])
        withoutPaths = Directive("script-src", [DirectiveTest.sampleSrcExpr2.removePath()])
        assert withPaths.withoutPaths() == withoutPaths
        
    def testDirective_asBasicDirectives_single(self):
        assert Directive.INVALID().asBasicDirectives() == set([])
        assert Directive.EVAL_SCRIPT_BASE_RESTRICTION().asBasicDirectives() == set([])
        assert Directive.INLINE_SCRIPT_BASE_RESTRICTION().asBasicDirectives() == set([])
        assert Directive.INLINE_STYLE_BASE_RESTRICTION().asBasicDirectives() == set([])
        sampleDirective = Directive("img-src", [DirectiveTest.sampleSrcExpr1b])
        assert sampleDirective.asBasicDirectives() == set([sampleDirective])
        
    def testDirective_asBasicDirectives_multiple(self):
        sampleDirective = Directive("script-src", [SelfSourceExpression.SELF(),
                                                   DirectiveTest.sampleSrcExpr1a,
                                                   DirectiveTest.sampleSrcExpr2,
                                                   DirectiveTest.sampleSrcExpr3])
        assert sampleDirective.asBasicDirectives() == set([Directive("script-src", [SelfSourceExpression.SELF()]),
                                                           Directive("script-src", [DirectiveTest.sampleSrcExpr1a]),
                                                           Directive("script-src", [DirectiveTest.sampleSrcExpr2]),
                                                           Directive("script-src", [DirectiveTest.sampleSrcExpr3])])
        
    def testDirective_isBasicDirective(self):
        assert Directive.INVALID().isBasicDirective() == False
        assert Directive.EVAL_SCRIPT_BASE_RESTRICTION().isBasicDirective() == False
        assert Directive("default-src", ()).isBasicDirective() == True
        assert Directive("script-src", [DirectiveTest.sampleSrcExpr2]).isBasicDirective() == True
        assert Directive("object-src", [DirectiveTest.sampleSrcExpr2,
                                        DirectiveTest.sampleSrcExpr3]).isBasicDirective() == False
        
    
    def testDirectiveParser_parse_empty(self):
        assert DirectiveParser(strict=True).parse("  ") == Directive.INVALID()
        assert DirectiveParser(strict=False).parse("  ") == Directive.INVALID()
        assert DirectiveParser(strict=True).parse("img-src ") == Directive.INVALID()
        assert DirectiveParser(strict=False).parse("img-src ") == Directive.INVALID()
        
    def testDirectiveParser_parse_standard(self):
        assert DirectiveParser(strict=True).parse("default-src https: 'unsafe-inline' 'unsafe-eval'") \
            == Directive("default-src", [URISourceExpression("https", None, None, None),
                                         SourceExpression.UNSAFE_INLINE(), SourceExpression.UNSAFE_EVAL()])
        assert DirectiveParser(strict=True).parse("default-src 'self'") \
            == Directive("default-src", [SelfSourceExpression.SELF()])
        assert DirectiveParser(strict=True).parse("img-src *") \
            == Directive("img-src", [URISourceExpression(None, "*", None, None)])
        assert DirectiveParser(strict=True).parse("object-src media1.example.com media2.example.com *.cdn.example.com") \
            == Directive("object-src", [URISourceExpression(None, "media1.example.com", None, None),
                                        URISourceExpression(None, "media2.example.com", None, None),
                                        URISourceExpression(None, "*.cdn.example.com", None, None)])
        
    def testDirectiveParser_parse_whitespaceRemoval(self):
        """Whitespace is properly removed."""
        directive = "img-src  'self'  https://abc.cloudfront.net/the-path chrome-extension: data: https://def.cloudfront.net/another-path "
        directiveClean = "img-src 'self' chrome-extension: data: https://abc.cloudfront.net/the-path https://def.cloudfront.net/another-path"
        cspDirective = DirectiveParser().parse(directive)
        assert cspDirective.getType() == "img-src"
        assert cspDirective.getWhitelistedSourceExpressions() == set([SelfSourceExpression.SELF(),
                URISourceExpression("chrome-extension", None, None, None), URISourceExpression("data", None, None, None), 
                URISourceExpression("https", "abc.cloudfront.net", None, "/the-path"),
                URISourceExpression("https", "def.cloudfront.net", None, "/another-path")])
        assert str(cspDirective) == directiveClean
        cspDirectiveClean = DirectiveParser().parse(directiveClean)
        assert cspDirective == cspDirectiveClean
         
    def testDirectiveParser_parse_invalid(self):
        invalidDirective = "blah"
        assert DirectiveParser().parse(invalidDirective) is Directive.INVALID()
         
    def testDirectiveParser_parse_translate(self):
        """The old directive type 'xhr-src' is correctly rewritten to 'connect-src'."""
        translateDirective = "xhr-src http://localhost"
        cspTranslateDirective = DirectiveParser().parse(translateDirective)
        assert cspTranslateDirective == Directive("connect-src", (URISourceExpression("http", "localhost", None, None),))
         
    def testDirectiveParser_parse_ignore(self):
        """Report URIs are not supported in CSP Directives."""
        ignoredDirective = "report-uri http://localhost/saveme.exe"
        assert DirectiveParser().parse(ignoredDirective) is Directive.INVALID()
         
    def testDirectiveParser_parse_none(self):
        """Parse a 'none' value."""
        noneDirective = """default-src 'none' """
        cspNoneDirective = DirectiveParser().parse(noneDirective)
        assert cspNoneDirective == Directive("default-src", [])
        
    def testDirectiveParser_parse_none_syntaxerror_strict(self):
        """If 'none' appears in a directive parsed strictly, no other values are permitted."""
        noneDirectiveInvalid = """default-src http://one 'None' http://two"""
        assert DirectiveParser(strict=True).parse(noneDirectiveInvalid) \
            == Directive.INVALID()
            
    def testDirectiveParser_parse_none_syntaxerror_notstrict(self):
        """If 'none' appears in a directive not parsed strictly and other expressions occur, 'none' is ignored."""
        noneDirectiveInvalid = """default-src http://one 'None' http://two"""
        cspDirective = DirectiveParser(strict=False).parse(noneDirectiveInvalid)
        assert cspDirective == Directive("default-src", [URISourceExpression("http", "one", None, None),
                                                         URISourceExpression("http", "two", None, None)])
        
    def testDirectiveParser_parse_invalidSourceExpression_strict(self):
        """In strict mode, only valid source expressions may be used."""
        invalidDirective = """img-src http://url 'blah'"""
        assert DirectiveParser(strict=True).parse(invalidDirective) \
            == Directive.INVALID()
            
    def testDirectiveParser_parse_invalidSourceExpression_notstrict(self):
        """In non-strict mode, invalid source expressions are ignored."""
        invalidDirective = """img-src http://url 'blah'"""
        cspDirective = DirectiveParser(strict=False).parse(invalidDirective)
        assert cspDirective == Directive("img-src", [URISourceExpression("http", "url", None, None)])
                    
    def testDirectiveParser_parse_inline(self):
        """'unsafe-inline' keyword allowed only in 'script-src' and 'style-src' and 'default-src'"""
        scriptSrcWithInline = """script-src 'self' 'unsafe-inline' http://me.com/"""
        styleSrcWithInline = """style-src 'unsafe-inline' http://other"""
        styleSrcWithInlineOnly = """style-src 'unsafe-inline'"""
        defaultSrcWithInlineOnly = """default-src 'unsafe-inline'"""
        invalidObjectSrcWithInline = """object-src 'self' 'unsafe-inline'"""
        invalidObjectSrcWithInlineOnly = """object-src 'unsafe-inline'"""
        assert str(DirectiveParser().parse(scriptSrcWithInline)) == scriptSrcWithInline
        assert str(DirectiveParser().parse(styleSrcWithInline)) == styleSrcWithInline
        assert str(DirectiveParser().parse(styleSrcWithInlineOnly)) == styleSrcWithInlineOnly
        assert str(DirectiveParser().parse(defaultSrcWithInlineOnly)) == defaultSrcWithInlineOnly
        assert DirectiveParser(strict=True).parse(invalidObjectSrcWithInline) \
            == Directive.INVALID()
        assert str(DirectiveParser(strict=False).parse(invalidObjectSrcWithInline)) \
            == "object-src 'self'"
        assert DirectiveParser(strict=True).parse(invalidObjectSrcWithInlineOnly) \
            == Directive.INVALID()
        assert str(DirectiveParser(strict=False).parse(invalidObjectSrcWithInlineOnly)) \
            == "object-src 'none'"
     
    def testDirectiveParser_parse_eval(self):
        """'unsafe-eval' keyword allowed only in 'script-src' and 'default-src'"""
        scriptSrcWithEval = """script-src 'self' 'unsafe-eval' 'unsafe-inline'"""
        scriptSrcWithEvalOnly = """script-src 'unsafe-eval'"""
        defaultSrcWithInlineAndEvalOnly = """default-src 'unsafe-eval' 'unsafe-inline'"""
        invalidImgSrcWithEval = """img-src http://example/path 'unsafe-eval'"""
        assert str(DirectiveParser().parse(scriptSrcWithEval)) == scriptSrcWithEval
        assert str(DirectiveParser().parse(scriptSrcWithEvalOnly)) == scriptSrcWithEvalOnly
        assert str(DirectiveParser().parse(defaultSrcWithInlineAndEvalOnly)) \
            == defaultSrcWithInlineAndEvalOnly
        assert DirectiveParser(strict=True).parse(invalidImgSrcWithEval) \
            == Directive.INVALID()
        assert str(DirectiveParser(strict=False).parse(invalidImgSrcWithEval)) \
            == "img-src http://example/path"
            
    def testDirectiveParser_parse_inlineStyleBaseRestriction(self):
        """The Firefox value 'inline style base restriction' for the 'violated-directive' field is parsed
        correctly."""
        firefoxViolatedDirective = "inline style base restriction"
        assert DirectiveParser().parse(firefoxViolatedDirective) \
                == Directive.INLINE_STYLE_BASE_RESTRICTION()
                
    def testDirectiveParser_parse_inlineScriptBaseRestriction(self):
        """The Firefox value 'inline script base restriction' for the 'violated-directive' field is parsed
        correctly."""
        firefoxViolatedDirective = "inline script base restriction"
        assert DirectiveParser().parse(firefoxViolatedDirective) \
                == Directive.INLINE_SCRIPT_BASE_RESTRICTION()
                
    def testDirectiveParser_parse_evalScriptBaseRestriction(self):
        """The Firefox value 'eval script base restriction' for the 'violated-directive' field is parsed
        correctly."""
        firefoxViolatedDirective = "eval script base restriction"
        assert DirectiveParser().parse(firefoxViolatedDirective) \
                == Directive.EVAL_SCRIPT_BASE_RESTRICTION()


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
