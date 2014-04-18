'''
Tests for log.py

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''

import unittest
from csp.report import Report
from csp.policy import Policy
from csp.directive import Directive
from csp.sourceexpression import SourceExpression, URISourceExpression
from csp.uri import URI
from csp.log import LogEntry, LogEntryParser
import pytest


class LogEntryTest(unittest.TestCase):
    
    starSourceExpr = URISourceExpression(None, "*", None, None)
    strLogEntry = """{"csp-report": {"blocked-uri": "", "document-uri": "http://seclab.nu/csp-test.html", """ \
                        + """"original-policy": "default-src *; script-src 'unsafe-eval' *; style-src *", """ \
                        + """"referrer": "", "status-code": 200, "violated-directive": "style-src *"}, """ \
                        + """"header-type": "webkit", "http-user-agent": """ \
                        + """"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_5) AppleWebKit/537.36 (KHTML, """ \
                        + """like Gecko) Chrome/31.0.1650.63 Safari/537.36", "policy-type": "inline", """ \
                        + """"remote-addr": "1.2.3.4", "timestamp-utc": "2013-12-14 01:02:03.456789"}"""
    logEntryData = {u"csp-report": Report({u"document-uri": URI("http", "seclab.nu", None, u"/csp-test.html"),
                                                  u"referrer": URI.EMPTY(),
                                                  u"violated-directive": Directive("style-src",
                                                                                  (starSourceExpr,)),
                                                  u"original-policy": Policy((Directive("default-src",
                                                                                       (starSourceExpr,)),
                                                                             Directive("script-src",
                                                                                       (starSourceExpr,
                                                                                        SourceExpression.UNSAFE_EVAL())),
                                                                             Directive("style-src",
                                                                                       (starSourceExpr,)))),
                                                  u"blocked-uri": URI.EMPTY(),
                                                  u"status-code": 200                                                      
                                                  }),
                            u"remote-addr": u"1.2.3.4",
                            u"http-user-agent": u"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_5) " \
                                + u"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36",
                            u"timestamp-utc": u"2013-12-14 01:02:03.456789",
                            u"policy-type": u"inline",
                            u"header-type": u"webkit"
                            }
    cspLogEntry = LogEntry(logEntryData)
    
    def testLogEntry_str_invalid(self):
        assert str(LogEntry.INVALID()) == "[invalid]"
        
    def testLogEntry_str_regular(self):
        assert str(LogEntryTest.cspLogEntry) == LogEntryTest.strLogEntry

    def testLogEntry_dict_iterateAndImmutable(self):
        assert len(LogEntryTest.cspLogEntry) == 6
        assert "http-user-agent" in LogEntryTest.cspLogEntry
        assert LogEntryTest.cspLogEntry["remote-addr"] == "1.2.3.4"
        for key in LogEntryTest.cspLogEntry.keys():
            assert key in ("csp-report", "remote-addr", "http-user-agent", "timestamp-utc", "policy-type", "header-type")
        with pytest.raises(TypeError):
            LogEntryTest.cspLogEntry["csp-report"] = None
        with pytest.raises(TypeError):
            LogEntryTest.cspLogEntry["something-else"] = 123
            
    def testLogEntry_eq(self):
        assert LogEntryTest.cspLogEntry != LogEntry.INVALID()
        
    def testLogEntry_generatePolicy_standard(self):
        assert LogEntryTest.cspLogEntry.generatePolicy() == Policy([Directive("style-src", [SourceExpression.UNSAFE_INLINE()])])
        
    def testLogEntry_generatePolicy_invalid(self):
        assert LogEntry.INVALID().generatePolicy() == Policy.INVALID()
        
    def testLogEntry_generatePolicy_incomplete(self):
        logEntryNoReport = LogEntryTest.logEntryData.copy()
        del logEntryNoReport['csp-report']
        logEntryNoPolicyType = LogEntryTest.logEntryData.copy()
        del logEntryNoPolicyType['policy-type']
        assert LogEntry(logEntryNoReport).generatePolicy() == Policy.INVALID()
        assert LogEntry(logEntryNoPolicyType).generatePolicy() == Policy.INVALID()
        
    def testLogEntryParser_parse(self):
        parser = LogEntryParser(strict=True)
        parsed = parser.parseString(LogEntryTest.strLogEntry)
        print parsed._entryData
        print LogEntryTest.cspLogEntry._entryData
        print parsed._entryData['csp-report'] == LogEntryTest.cspLogEntry._entryData['csp-report']
        assert parsed == LogEntryTest.cspLogEntry
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
