'''
Tests for fileio.py

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''

import unittest
from csp.tools.fileio import DataWriter, ReportDataReader, LogEntryDataReader, PolicyDataReader
from csp.report import Report
from csp.directive import Directive
from csp.sourceexpression import SourceExpression, URISourceExpression
from csp.policy import Policy
from csp.uri import URI
from ..test_log import LogEntryTest
import pytest


class ReportDataReaderTest(unittest.TestCase):
    
    sampleURI1a = URI("http", "seclab.nu", None, None, None)
    sampleURI1b = URI("http", "seclab.nu", None, None, None)
    sampleURI2 = URI("http", "seclab.nu", None, "/blocked", "query")
    sampleDirective1a = Directive("default-src", ())
    sampleDirective1b = Directive("default-src", ())
    sampleDirective2a = Directive("script-src", (SourceExpression.UNSAFE_INLINE(),))
    sampleDirective2b = Directive("script-src", (SourceExpression.UNSAFE_INLINE(),))
    samplePolicy1a = Policy((sampleDirective1a, sampleDirective2a))
    samplePolicy1b = Policy((sampleDirective1b, sampleDirective2b))
    samplePolicy2 = Policy((sampleDirective1a,))
    
    @pytest.fixture(autouse=True)
    def initdir(self, tmpdir):
        tmpdir.chdir()

    def setUp(self):
        self.fileIn = ReportDataReader(True)
        self.filename = "encodingdecoding.dat"
        self.fileOut = DataWriter(self.filename)

    def tearDown(self):
        pass
        
    def testReportCreation(self):
        """Writes a Report and loads it back as an object."""
        report = Report({"abc": True, 
                         "def": 1, 
                         "ghi": "http://seclab.nu/",
                         "document-uri": ReportDataReaderTest.sampleURI1a,
                         "violated-directive": ReportDataReaderTest.sampleDirective1a,
                         "original-policy": ReportDataReaderTest.samplePolicy1a,
                         "blocked-uri": ReportDataReaderTest.sampleURI2})
        self.fileOut.storeAll([report])
        self.fileOut.close()
        dataOut = self.fileIn.loadAll(self.filename)
        assert len(dataOut) == 1
        print report
        print dataOut[0]
        assert report in dataOut


class LogEntryDataReaderTest(unittest.TestCase):
    
    @pytest.fixture(autouse=True)
    def initdir(self, tmpdir):
        tmpdir.chdir()

    def setUp(self):
        self.fileIn = LogEntryDataReader(True)
        self.filename = "logentrystorage.dat"
        self.fileOut = DataWriter(self.filename)
 
    def testReportCreation(self):
        """Writes a LogEntry and loads it back as an object."""
        self.fileOut.storeAll([LogEntryTest.cspLogEntry])
        self.fileOut.close()
        dataOut = self.fileIn.loadAll(self.filename)
        assert len(dataOut) == 1
        assert LogEntryTest.cspLogEntry in dataOut
        
        
class PolicyDataReaderTest(unittest.TestCase):
    
    samplePolicy = Policy([Directive("default-src", ()),
                           Directive("style-src", [SourceExpression.UNSAFE_INLINE()]),
                           Directive("img-src", [URISourceExpression(None, "seclab.nu", "*", None)])
                           ])
        
    @pytest.fixture(autouse=True)
    def initdir(self, tmpdir):
        tmpdir.chdir()

    def setUp(self):
        self.fileIn = PolicyDataReader(True)
        self.filename = "policystorage.dat"
        self.fileOut = DataWriter(self.filename)
 
    def testReportCreation(self):
        """Writes a LogEntry and loads it back as an object."""
        self.fileOut.storeAll([PolicyDataReaderTest.samplePolicy])
        self.fileOut.close()
        dataOut = self.fileIn.loadAll(self.filename)
        assert len(dataOut) == 1
        assert PolicyDataReaderTest.samplePolicy in dataOut
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
