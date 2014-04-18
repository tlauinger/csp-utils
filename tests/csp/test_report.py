# -*- coding: utf-8 -*-
'''
Tests for report.py

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''

import unittest
from csp.report import Report, ReportParser
from csp.policy import Policy
from csp.directive import Directive
from csp.sourceexpression import SourceExpression, SelfSourceExpression, URISourceExpression
from csp.uri import URI
import pytest
import json


class ReportTest(unittest.TestCase):
    
    sampleURI1a = URI("http", "seclab.nu", None, None, None)
    sampleURI1b = URI("http", "seclab.nu", None, None, None)
    sampleURI2 = URI("https", "seclab.ccs.neu.edu", None, None, "query")
    sampleDirective1a = Directive("default-src", (SelfSourceExpression.SELF(),))
    sampleDirective1b = Directive("default-src", (SelfSourceExpression(),))
    sampleDirective2a = Directive("script-src", (SourceExpression.UNSAFE_INLINE(),))
    sampleDirective2b = Directive("script-src", (SourceExpression.UNSAFE_INLINE(),))
    sampleDirective3 = Directive("script-src", (URISourceExpression("http", "seclab.nu", None, None),))
    samplePolicy1a = Policy((sampleDirective1a, sampleDirective2a))
    samplePolicy1b = Policy((sampleDirective1b, sampleDirective2b))
    
    def testReport_str_invalid(self):
        assert str(Report.INVALID()) == "[invalid]"
        
    def testReport_str_regular(self):
        """Extended object types should be serialised to strings when getting the report as a string."""
        report = Report({"violated-directive": ReportTest.sampleDirective2a,
                         "original-policy": ReportTest.samplePolicy1a})
        assert str(report) == """{"original-policy": "default-src 'self'; script-src 'unsafe-inline'",""" \
                                + """ "violated-directive": "script-src 'unsafe-inline'"}"""

    def testReport_str_primitives(self):
        """A Report with basic data types in it (instead of strings) should have them serialised
        to JSON-supported basic data types, not all strings."""
        report = Report({"abc": True, "def": 1, "ghi": ReportTest.sampleURI1a})
        expected = """{"abc": true, "def": 1, "ghi": "http://seclab.nu"}"""
        assert str(report) == expected

    def testReport_dict_iterateAndImmutable(self):
        report = Report({"violated-directive": ReportTest.sampleDirective2a,
                         "original-policy": ReportTest.samplePolicy1a})
        assert len(report) == 2
        assert "violated-directive" in report
        assert report["violated-directive"] == ReportTest.sampleDirective2a
        assert "original-policy" in report
        assert report["original-policy"] == ReportTest.samplePolicy1a
        for (key, value) in report.iteritems():
            assert key in ("violated-directive", "original-policy")
            assert value in (ReportTest.sampleDirective2a, ReportTest.samplePolicy1a)
        with pytest.raises(TypeError):
            report["original-policy"] = None
        with pytest.raises(TypeError):
            report["something-else"] = 123
            
    def testReport_eq(self):
        report1a = Report({"violated-directive": ReportTest.sampleDirective2a,
                         "original-policy": ReportTest.samplePolicy1a})
        report1b = Report({"violated-directive": ReportTest.sampleDirective2b,
                         "original-policy": ReportTest.samplePolicy1b})
        report2 = Report({"violated-directive": ReportTest.sampleDirective1a,
                         "original-policy": ReportTest.samplePolicy1a})
        
        assert report1a == report1b
        assert hash(report1a) == hash(report1b)
        assert report1a != report2
        assert report1a != Report.INVALID()
        assert report2 != Report.INVALID()
           
    def testReport_generatePolicy_regular(self):
        report = Report({"blocked-uri": ReportTest.sampleURI1a,
                         "violated-directive": ReportTest.sampleDirective2a,
                         "document-uri": ReportTest.sampleURI2
                        })
        assert report.generatePolicy("regular") == Policy([ReportTest.sampleDirective3])
    
    def testReport_generatePolicy_invalid(self):
        assert Report.INVALID().generatePolicy("regular") == Policy.INVALID()
        
    def testReport_generatePolicy_missingReportField(self):
        reportNoViolated = Report({"blocked-uri": ReportTest.sampleURI1a,
                                   "document-uri": ReportTest.sampleURI2
                                   })
        reportNoBlocked = Report({"violated-directive": ReportTest.sampleDirective2a,
                                   "document-uri": ReportTest.sampleURI2
                                   })
        assert reportNoViolated.generatePolicy("regular") == Policy.INVALID()
        assert reportNoBlocked.generatePolicy("regular") == Policy.INVALID()
        
    def testReport_generatePolicy_fromInvalidDirectiveResult(self):
        reportDefaultSrc = Report({"blocked-uri": ReportTest.sampleURI1a,
                                   "violated-directive": ReportTest.sampleDirective1a,
                                   "document-uri": ReportTest.sampleURI2
                                   })
        assert reportDefaultSrc.generatePolicy("regular") == Policy.INVALID()
        
    def testReport_generatePolicy_wrongDocumentURI(self):
        reportEmptyDocument = Report({"blocked-uri": ReportTest.sampleURI1a,
                                      "violated-directive": ReportTest.sampleDirective1a,
                                      "document-uri": URI.EMPTY()
                                      })
        assert reportEmptyDocument.generatePolicy("regular") == Policy.INVALID()    
        
    def testReportParser_parse_typeFields(self):
        """Check that type indications for fields are properly parsed."""
        report = """{"uri": "https://seclab.ccs.neu.edu?query", "directive": "script-src 'unsafe-inline'",""" \
                + """ "policy": "script-src 'unsafe-inline'; default-src 'self'",""" \
                + """ "nothing": "123"}"""
        cspReport = ReportParser(uriKeys=["uri", "url"], directiveKeys=["directive"], policyKeys=["policy"], 
                                 requiredKeys=[], strict=True).parseString(report)
        expected = Report({"uri": ReportTest.sampleURI2,
                           "directive": ReportTest.sampleDirective2a,
                           "policy": ReportTest.samplePolicy1a,
                           "nothing": "123"})
        assert cspReport == expected
        
    def testReportParser_parse_stringVsJSON(self):
        """Ensure the string parsing returns the same result as JSON parsing."""
        reportJSON = {"something": 123, "uri": "http://seclab.nu"}
        reportString = """{"something": 123, "uri": "http://seclab.nu"}"""
        expected = Report({"something": 123, "uri": ReportTest.sampleURI1a})
        parser = ReportParser(uriKeys=["uri"], requiredKeys=[], strict=True)
        parsedFromJSON = parser.parseJsonDict(reportJSON)
        parsedFromString = parser.parseString(reportString)
        print parsedFromJSON
        print parsedFromString
        assert parsedFromJSON == parsedFromString
        assert parsedFromJSON == expected
        
    def testReportParser_parse_fieldNameReplacements(self):
        """Checks that old field names are replaced correctly."""
        report = """{"document-url": "http://seclab.nu", "original-policy": "default-src 'self'; script-src 'unsafe-inline'"}"""
        expected = Report({"document-uri": ReportTest.sampleURI1a,
                           "original-policy": ReportTest.samplePolicy1a})
        parser = ReportParser(uriKeys=["document-uri"], policyKeys=["original-policy"],
                              requiredKeys=["document-uri", "original-policy"],
                              strict=True, keyNameReplacements={"document-url": "document-uri"})
        cspReport = parser.parseString(report)
        assert cspReport == expected
        
    def testReportParser_parse_requiredFields(self):
        """Required fields must be present even if strict=False."""
        report = """{"this-is": "a quite empty report"}"""
        expected = Report({"this-is": "a quite empty report"})
        assert ReportParser(requiredKeys=[], strict=False).parseString(report) == expected
        assert ReportParser(requiredKeys=["does-not-exist"], strict=False).parseString(report) == Report.INVALID()
        
    def testReportParser_parse_emptyOrSelfURI(self):
        """This tests that the internal settings of the URI parser are chosen such that empty or self URIs are
        correctly handled."""
        report = """{"empty-uri": "", "self-uri": "self", "document-uri": "http://seclab.nu"}"""
        expected = Report({"empty-uri": URI.EMPTY(), "self-uri": ReportTest.sampleURI1a,
                           "document-uri": ReportTest.sampleURI1a})
        assert ReportParser(requiredKeys=[], strict=True, uriKeys=["empty-uri", "self-uri", "document-uri"]) \
                        .parseString(report) == expected
                            
    def testReportParser_parse_failIfStrict(self):
        """The report must be declared invalid in strict mode when a child element is invalid."""
        report = """{"invalid-policy": "awesomeness-src 'self'", "example": true}"""
        assert ReportParser(requiredKeys=[], strict=True, policyKeys=["invalid-policy"]) \
                        .parseString(report) == Report.INVALID()
                            
    def testReportParser_parse_skipIfNotStrict(self):
        """Invalid portions of the report must be skipped in non-strict mode."""
        report = """{"invalid-policy": "awesomeness-src 'self'", "example": true}"""
        expected = Report({"example": True})
        assert ReportParser(requiredKeys=[], strict=False, policyKeys=["invalid-policy"]) \
                        .parseString(report) == expected
                            
    def testReportParser_parse_inferSelfURI(self):
        """Tests if the self URI is correctly inferred from the "document-uri" field (even
        after renaming)."""
        report = """{"violated-directive": "default-src 'self'", "referrer": "",""" \
                + """ "blocked-uri": "self", "document-URL":""" \
                + """ "http://seclab.nu"}"""
        expected = Report({"violated-directive": ReportTest.sampleDirective1a,
                           "referrer": URI.EMPTY(),
                           "blocked-uri": ReportTest.sampleURI1a,
                           "document-uri": ReportTest.sampleURI1a})
        parser = ReportParser(requiredKeys=["violated-directive", "document-uri", "blocked-uri"], strict=True,
                              directiveKeys=["violated-directive"], 
                              uriKeys=["referrer", "blocked-uri", "document-uri"],
                              keyNameReplacements={'document-url': 'document-uri'})
        cspReport = parser.parseString(report)
        assert cspReport == expected
        
    def testReportParser_parse_selfURIFailStrict(self):
        """Tests that parsing fails if strict and no document-uri but another 'self' URI."""
        report = """{"blocked-uri": "self", "other": "value"}"""
        parser = ReportParser(requiredKeys=[], strict=True,
                              uriKeys=["blocked-uri", "document-uri"])
        cspReport = parser.parseString(report)
        assert cspReport == Report.INVALID()
        
    def testReportParser_parse_selfURISkipStrict(self):
        """Tests that parsing fails if strict and no document-uri but another 'self' URI."""
        report = """{"blocked-uri": "self", "other": "value"}"""
        expected = Report({"other": "value"})
        parser = ReportParser(requiredKeys=[], strict=False,
                              uriKeys=["blocked-uri", "document-uri"])
        cspReport = parser.parseString(report)
        assert cspReport == expected
            
    def testReportParser_parse_unicode(self):
        """The JSON deserialiser returns strings as unicode objects. Check that they are correctly parsed in URIs."""
        fullReport = """{"remote-addr": "XXX", "policy-type": "regular", "http-user-agent":""" \
                    + """ "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:27.0) Gecko/20100101 Firefox/27.0",""" \
                    + """ "timestamp-utc": "2014-03-01 12:13:14.156789", "csp-report": {"violated-directive":""" \
                    + """ "img-src 'none'", "referrer": "http://handbook5.com/a/a-security-analysis-of-amazon%E2%80%99s-elastic-compute-cloud-service-w14847.html",""" \
                    + """ "blocked-uri": "http://www.iseclab.org/images/anr.png", "document-uri":""" \
                    + """ "http://www.iseclab.org/?p"}, "header-type": "standard"}"""
        expected = Report({"violated-directive": Directive("img-src", ()),
                           "referrer": URI("http", "handbook5.com", None, u"/a/a-security-analysis-of-amazon’s-elastic-compute-cloud-service-w14847.html"),
                           "blocked-uri": URI("http", "www.iseclab.org", None, u"/images/anr.png"),
                           "document-uri": URI("http", "www.iseclab.org", None, u"/", "p")                           
                           })
        parser = ReportParser(requiredKeys=[])
        jsonReport = json.loads(fullReport)
        cspReport = parser.parseJsonDict(jsonReport["csp-report"])
        assert cspReport == expected


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
