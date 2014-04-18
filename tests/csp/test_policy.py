'''
Tests for policy.py

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''

import unittest
from csp.policy import Policy, PolicyParser
from csp.directive import Directive
from csp.sourceexpression import SourceExpression, SelfSourceExpression, URISourceExpression
from csp.uri import URI


class PolicyTest(unittest.TestCase):
    
    sampleURI1a = URI("http", "seclab.nu", None, None, None)
    sampleURI1b = URI("http", "seclab.nu", None, None, None)
    sampleURI2 = URI("http", "seclab.ccs.neu.edu", None, None, None)
    sampleSourceExpression1 = URISourceExpression("http", "seclab.nu", None, None)
    sampleSourceExpression2 = SelfSourceExpression.SELF()
    sampleDirective1a = Directive("default-src", (URISourceExpression("http", "seclab.nu", None, None),))
    sampleDirective1b = Directive("default-src", (URISourceExpression("http", "seclab.nu", None, None),))
    sampleDirective2 = Directive("script-src", (SourceExpression.UNSAFE_INLINE(),))
    sampleDirective3 = Directive("img-src", (URISourceExpression(None, "*", None, None),))
    sampleDirective4 = Directive("img-src", ())
    sampleDirective5 = Directive("connect-src", (SelfSourceExpression.SELF(),
                                                 URISourceExpression("chrome-extension", None, None, None),
                                                 URISourceExpression("https", "abc.seclab.nu", None, "/path")))
    sampleDirective6 = Directive("style-src", (SourceExpression.UNSAFE_INLINE(), SelfSourceExpression.SELF()))
    sampleDirective7 = Directive("script-src", (SourceExpression.UNSAFE_EVAL(),))
    sampleDirective8 = Directive("style-src", (SelfSourceExpression.SELF(),))
    sampleDirective9 = Directive("default-src", (SourceExpression.UNSAFE_INLINE(),))
    
    def testPolicy_str_invalid(self):
        assert str(Policy.INVALID()) == "[invalid]"
        
    def testPolicy_str_empty(self):
        assert str(Policy(())) == ""
        
    def testPolicy_str_normal(self):
        pol = Policy((PolicyTest.sampleDirective1a, PolicyTest.sampleDirective2, PolicyTest.sampleDirective3))
        assert str(pol) == "default-src http://seclab.nu; img-src *; script-src 'unsafe-inline'"
    
    def testPolicy_eq(self):
        pol1a = Policy((PolicyTest.sampleDirective1a, PolicyTest.sampleDirective2, PolicyTest.sampleDirective3))
        pol1b = Policy((PolicyTest.sampleDirective1b, PolicyTest.sampleDirective2, PolicyTest.sampleDirective3))
        pol2 = Policy((PolicyTest.sampleDirective2, PolicyTest.sampleDirective3))
        assert Policy.INVALID() == Policy.INVALID()
        assert pol1a == pol1b
        assert hash(pol1a) == hash(pol1b)
        assert pol1a != pol2
    
    def testPolicy_init_duplicateType(self):
        pol = Policy((PolicyTest.sampleDirective1a, PolicyTest.sampleDirective3, PolicyTest.sampleDirective4))
        directives = pol.getDirectives()
        assert PolicyTest.sampleDirective1a in directives and (PolicyTest.sampleDirective3 in directives \
                                                              or PolicyTest.sampleDirective4 in directives)
        
    def testPolicy_init_duplicateDirective(self):
        pol = Policy((PolicyTest.sampleDirective1a, PolicyTest.sampleDirective1b, PolicyTest.sampleDirective2))
        assert pol == Policy((PolicyTest.sampleDirective1a, PolicyTest.sampleDirective2))
        assert pol == Policy((PolicyTest.sampleDirective1b, PolicyTest.sampleDirective2))
        
    def testPolicy_init_noDuplicatesHere(self):
        directives = set([PolicyTest.sampleDirective1a, PolicyTest.sampleDirective2, PolicyTest.sampleDirective5])
        pol = Policy(directives)
        assert pol.getDirectives() == directives
        
    def testPolicy_init_removeNotRegularDirective(self):
        pol = Policy([PolicyTest.sampleDirective1a, Directive.INVALID(), Directive.EVAL_SCRIPT_BASE_RESTRICTION()])
        expected = Policy([PolicyTest.sampleDirective1a])
        assert pol == expected
        
    def testPolicy_matches_invalid(self):
        """An invalid policy matches nothing."""
        selfURI = PolicyTest.sampleURI2
        assert not Policy.INVALID().matches(PolicyTest.sampleURI1a, "script-src", selfURI)
        assert not Policy.INVALID().matches(URI.INVALID(), "script-src", selfURI)
        assert not Policy.INVALID().matches(URI.EMPTY(), "script-src", selfURI)
        assert not Policy.INVALID().matches(URI.INLINE(), "script-src", selfURI)
        assert not Policy.INVALID().matches(URI.EVAL(), "script-src", selfURI)
        
    def testPolicy_matches_matchingDirectiveType(self):
        """Policy contains directive of resource type that matches."""
        pol = Policy((PolicyTest.sampleDirective1a, PolicyTest.sampleDirective5))
        selfURI = PolicyTest.sampleURI2
        assert pol.matches(URI("https", "abc.seclab.nu", 443, "/path", "some-query"), "connect-src", selfURI)
        
    def testPolicy_matches_nonMatchingDirectiveTypeButDefaultMatches(self):
        """Policy contains directive of resource type that does not match
        and default directive that does match, but it should not be applied."""
        pol = Policy((PolicyTest.sampleDirective1a, PolicyTest.sampleDirective5))
        selfURI = PolicyTest.sampleURI2
        assert not pol.matches(PolicyTest.sampleURI1a, "connect-src", selfURI)
        
    def testPolicy_matches_defaultSrcMatches(self):
        """Policy contains no directive of resource type, but a default directive that matches."""
        pol = Policy((PolicyTest.sampleDirective1a, PolicyTest.sampleDirective5))
        selfURI = PolicyTest.sampleURI2
        assert pol.matches(PolicyTest.sampleURI1a, "script-src", selfURI)
        
    def testPolicy_matches_defaultSrcNoMatch(self):
        """Policy contains no directive of resource type, but a default directive.
        Default-src does not match."""
        pol = Policy((PolicyTest.sampleDirective1a,))
        selfURI = PolicyTest.sampleURI1a
        assert not pol.matches(PolicyTest.sampleURI2, "img-src", selfURI)
        
    def testPolicy_matches_defaultSrcNotUsable(self):
        """Policy contains no directive of resource type, but a default directive.
        Default-src cannot be used in this case because not allowed for resource type."""
        pol = Policy((PolicyTest.sampleDirective1a,))
        selfURI = PolicyTest.sampleURI2
        assert not pol.matches(PolicyTest.sampleURI1a, "form-action", selfURI)
        
    def testPolicy_matches_defaultSrcNotSpecified_match(self):
        """Policy contains no directive of resource type, and no default directive either.
        Should assume 'default-src *' (match for regular resources)."""
        pol = Policy((PolicyTest.sampleDirective5,))
        selfURI = PolicyTest.sampleURI1a
        assert pol.matches(PolicyTest.sampleURI2, "script-src", selfURI)
    
    def testPolicy_matches_defaultSrcNotSpecified_noMatch(self):
        """Policy contains no directive of resource type, and no default directive either.
        Should assume 'default-src *' (no match for inline/eval resources)."""
        pol = Policy((PolicyTest.sampleDirective5,))
        selfURI = PolicyTest.sampleURI1a
        assert not pol.matches(URI.INLINE(), "script-src", selfURI)
        assert not pol.matches(URI.EVAL(), "script-src", selfURI)
        
    def testPolicyParser_parse_normal(self):
        simplePolicy = """connect-src 'self' https://abc.seclab.nu/path chrome-extension:; img-src 'none'"""
        cspSimplePolicy = PolicyParser().parse(simplePolicy)
        print cspSimplePolicy
        assert cspSimplePolicy == Policy([PolicyTest.sampleDirective4, PolicyTest.sampleDirective5])
                
    def testPolicyParser_parse_strict_onlyValidDirectives(self):
        """Ensures that a CSP policy does not parse in strict mode if it contains an invalid directive."""
        policy = """img-src 'none'; script-src"""
        cspPolicy = PolicyParser(strict=True).parse(policy)
        assert cspPolicy == Policy.INVALID()
        
    def testPolicyParser_parse_nonstrict_onlyValidDirectives(self):
        """Ensures that a CSP policy does ignore invalid portions in non-strict mode if it contains an invalid directive."""
        policy = """img-src 'none'; script-src"""
        cspPolicy = PolicyParser(strict=False).parse(policy)
        assert cspPolicy == Policy([PolicyTest.sampleDirective4])
        
    def testPolicyParser_parse_ignoredDirective(self):
        """Ensure that unsupported directives ('report-uri' etc.) are skipped without
         causing an error."""
        policy = """img-src *; report-uri /csp.cgi"""
        cspPolicy = PolicyParser(strict=True, ignoredTypes=("report-uri",)).parse(policy)
        assert cspPolicy == Policy([PolicyTest.sampleDirective3])
         
    def testPolicyParser_parse_defaultSrcRewriting(self):
        """The default directive is used for each type that is not specifically defined (if the flag is enabled)."""
        policy = """default-src 'self' http://seclab.nu; connect-src 'self' https://abc.seclab.nu/path chrome-extension:"""
        cspPolicy = PolicyParser(expandDefaultSrc=True,
                                 defaultSrcTypes=("img-src", "connect-src")).parse(policy)
        assert cspPolicy == Policy([PolicyTest.sampleDirective5,
                                    Directive("img-src", [PolicyTest.sampleSourceExpression1,
                                                          PolicyTest.sampleSourceExpression2])])
    
    def testPolicyParser_parse_noDefaultSrcRewriting(self):
        policy = """default-src 'self' http://seclab.nu"""
        cspPolicy = PolicyParser(expandDefaultSrc=False,
                                 defaultSrcTypes=("img-src", "connect-src")).parse(policy)
        assert cspPolicy == Policy([Directive("default-src", [PolicyTest.sampleSourceExpression1,
                                                              PolicyTest.sampleSourceExpression2])])
         
    def testPolicyParser_parse_duplicates(self):
        """The CSP standard mandates that only the first directive of each type should be used."""
        duplicatePolicy = """connect-src 'self' chrome-extension: https://abc.seclab.nu/path; """ \
                            + """font-src 'self' http://seclab.nu; """ \
                            + """connect-src 'self' https://example.com"""
        cspPolicy = PolicyParser().parse(duplicatePolicy)
        assert cspPolicy == Policy([PolicyTest.sampleDirective5,
                                    Directive("font-src", [PolicyTest.sampleSourceExpression1,
                                                           PolicyTest.sampleSourceExpression2])])
          
    def testPolicy_combinedPolicy_normal(self):
        pol1 = Policy([PolicyTest.sampleDirective6, PolicyTest.sampleDirective2, PolicyTest.sampleDirective3])
        pol2 = Policy([PolicyTest.sampleDirective4, PolicyTest.sampleDirective7])
        expected = Policy([PolicyTest.sampleDirective6, PolicyTest.sampleDirective3,
                           Directive("script-src", [SourceExpression.UNSAFE_EVAL(), SourceExpression.UNSAFE_INLINE()])])
        assert pol1.combinedPolicy(pol1) == pol1
        assert pol2.combinedPolicy(pol2) == pol2
        assert pol1.combinedPolicy(pol2) == expected
        assert pol2.combinedPolicy(pol1) == expected
         
    def testPolicy_combinedPolicy_invalidPolicy(self):
        pol = Policy([PolicyTest.sampleDirective1a, PolicyTest.sampleDirective2, PolicyTest.sampleDirective3])
        assert pol.combinedPolicy(Policy.INVALID()) == Policy.INVALID()
        assert Policy.INVALID().combinedPolicy(pol) == Policy.INVALID()
         
    def testPolicy_combinedPolicy_invalidDefaultSrcAndOtherDirective(self):
        pol1 = Policy([PolicyTest.sampleDirective1a, PolicyTest.sampleDirective3])
        pol2 = Policy([PolicyTest.sampleDirective9])
        assert pol1.combinedPolicy(pol2) == Policy.INVALID()
        assert pol2.combinedPolicy(pol1) == Policy.INVALID()
        
    def testPolicy_combinedPolicy_invalidDefaultSrcInOnePolicyOnly(self):
        pol1 = Policy([PolicyTest.sampleDirective3])
        pol2 = Policy([PolicyTest.sampleDirective9])
        assert pol1.combinedPolicy(pol2) == Policy.INVALID()
        assert pol2.combinedPolicy(pol1) == Policy.INVALID()
        
    def testPolicy_combinedPolicy_validDefaultSrcOnly(self):
        """Combination of two policies with default directive is possible only if both policies contain
        only a default directive."""
        pol1 = Policy([PolicyTest.sampleDirective1a])
        pol2 = Policy([PolicyTest.sampleDirective9])
        expected = Policy([Directive("default-src", [PolicyTest.sampleSourceExpression1,
                                                     SourceExpression.UNSAFE_INLINE()])])
        assert pol1.combinedPolicy(pol2) == expected
        assert pol2.combinedPolicy(pol1) == expected
        
    def testPolicy_withoutPaths(self):
        withPaths = Policy([PolicyTest.sampleDirective3, PolicyTest.sampleDirective5, PolicyTest.sampleDirective7])
        withoutPaths = Policy([PolicyTest.sampleDirective3, PolicyTest.sampleDirective5.withoutPaths(), 
                               PolicyTest.sampleDirective7])
        assert withPaths.withoutPaths() == withoutPaths
        assert withoutPaths.withoutPaths() == withoutPaths
        assert Policy.INVALID().withoutPaths() == Policy.INVALID()
        
    def testPolicy_withoutPaths_schemeOnly(self):
        withPaths = Policy([PolicyTest.sampleDirective3, PolicyTest.sampleDirective5])
        withoutPaths = Policy([PolicyTest.sampleDirective3, PolicyTest.sampleDirective5.withoutPaths(["http"])])
        assert withPaths.withoutPaths(["http"]) == withoutPaths
        
    def testPolicy_asBasicPolicies_single(self):
        assert Policy.INVALID().asBasicPolicies() == set([])
        assert Policy([PolicyTest.sampleDirective1a]).asBasicPolicies() == set([Policy([PolicyTest.sampleDirective1a])])
        
    def testPolicy_asBasicPolicies_multiple(self):
        assert Policy([PolicyTest.sampleDirective1a,
                       PolicyTest.sampleDirective2]).asBasicPolicies() == set([Policy([PolicyTest.sampleDirective1a]),
                                                                               Policy([PolicyTest.sampleDirective2])])
                       
    def testPolicy_asBasicPolicies_recursive(self):
        expected = set(map(lambda direct: Policy((direct,)), PolicyTest.sampleDirective5.asBasicDirectives()))
        actual = Policy([PolicyTest.sampleDirective5]).asBasicPolicies()
        assert actual == expected
        
    def testPolicy_isBasicPolicy(self):
        assert Policy.INVALID().isBasicPolicy() == False
        assert Policy([PolicyTest.sampleDirective6]).isBasicPolicy() == False
        assert Policy([PolicyTest.sampleDirective1a]).isBasicPolicy() == True
        assert Policy([PolicyTest.sampleDirective2,
                       PolicyTest.sampleDirective4]).isBasicPolicy() == False
                       
    def testPolicy_isBasicNonePolicy(self):
        assert Policy.INVALID().isBasicNonePolicy() == False
        assert Policy([PolicyTest.sampleDirective6]).isBasicNonePolicy() == False
        assert Policy([PolicyTest.sampleDirective1a]).isBasicNonePolicy() == False
        assert Policy([PolicyTest.sampleDirective2,
                       PolicyTest.sampleDirective4]).isBasicNonePolicy() == False
        assert Policy([PolicyTest.sampleDirective4]).isBasicNonePolicy() == True
        
    def testPolicy_hasDefaultDirective(self):
        assert Policy.INVALID().hasDefaultDirective() == False
        assert Policy([PolicyTest.sampleDirective2,
                       PolicyTest.sampleDirective9]).hasDefaultDirective() == True
        assert Policy([PolicyTest.sampleDirective5,
                       PolicyTest.sampleDirective6]).hasDefaultDirective() == False
        
    def testPolicy_compareTo_invalid(self):
        assert Policy.INVALID().compareTo(Policy.INVALID()) == (set([]), set([]), set([]))
        pol = Policy([PolicyTest.sampleDirective9])
        assert pol.compareTo(Policy.INVALID()) == (set([]), set([]), set([]))
        assert Policy.INVALID().compareTo(pol) == (set([]), set([]), set([]))
        
    def testPolicy_compareTo_regular(self):
        pol1 = Policy([PolicyTest.sampleDirective7, PolicyTest.sampleDirective8])
        pol2 = Policy([PolicyTest.sampleDirective7, PolicyTest.sampleDirective9])
        assert pol1.compareTo(pol2) == (set([Policy([PolicyTest.sampleDirective7])]),
                                        set([Policy([PolicyTest.sampleDirective8])]),
                                        set([Policy([PolicyTest.sampleDirective9])]))
        assert pol2.compareTo(pol1) == (set([Policy([PolicyTest.sampleDirective7])]),
                                        set([Policy([PolicyTest.sampleDirective9])]),
                                        set([Policy([PolicyTest.sampleDirective8])]))
        assert pol1.compareTo(pol1) == (set([Policy([PolicyTest.sampleDirective7]),
                                             Policy([PolicyTest.sampleDirective8])]),
                                        set([]),
                                        set([]))
        
    def testPolicy_compareTo_recursive(self):
        pol1 = Policy([PolicyTest.sampleDirective6])
        pol2 = Policy([Directive("style-src", [SourceExpression.UNSAFE_INLINE()])])
        assert pol1.compareTo(pol2) == (set([pol2]),
                                        set([Policy([Directive("style-src", [SelfSourceExpression.SELF()])])]),
                                        set([]))


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
