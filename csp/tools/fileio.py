'''
Classes to read data from files and serialise objects into files.

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''

from csp.report import ReportParser, Report
from csp.log import LogEntryParser, LogEntry
from csp.policy import PolicyParser, Policy


class DataWriter(object):
    """
    Writes objects that support __str__ into a file, one object a line.
    """
    
    def __init__(self, filename):
        """Opens the given filename for writing. Can be used only until the file is closed."""
        self._f = open(filename, "w")
        
    def store(self, obj):
        """Writes the given object into a line in the file (appending to everything written so far)."""
        self._f.write(str(obj) + "\n")
       
    def storeAll(self, data):
        """Writes all the serialisable objects from the data structure to the file (appending to everything
        written so far)."""
        for obj in data:
            self.store(obj)
    
    def close(self):
        """Closes the underlying file."""
        self._f.close()
    
    def _encodeLineBreaks(self, inputstr):
        """Encodes % and \\r and \\n."""
        return inputstr.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    def _decodeLineBreaks(self, inputstr):
        """Decodes % (%25), \\r (%0D) and \\n (%0A)."""
        return inputstr.replace("%0A", "\n").replace("%0D", "\r").replace("%25", "%")


class DataReader(object):
    """
    Loads lines from a file, either line by line, or reading the entire file at once. Each
    line read from the file is passed to a callback function as a string.
    """
    
    def __init__(self, printErrorMessages=False):
        self._printErrorMessages = printErrorMessages

    def load(self, filename, callbackFunction):
        """
        Opens 'filename' and passes each non-empty line to 'callbackFunction'. Returns nothing.
        """
        f = open(filename, "r")
        for line in f:
            line = line.strip()
            if line != "":
                callbackFunction(line)
        f.close()
        
    def loadAll(self, filename):
        """
        Returns a list with all the non-empty lines in 'filename'.
        """
        data = []
        self.load(filename, lambda line: data.append(line))
        return data


class ReportDataReader(DataReader):
    '''
    Loads CSP violation reports from files. The file format is one JSON-encoded report per line.
    '''

    def __init__(self, printErrorMessages=False):
        DataReader.__init__(self, printErrorMessages)
        self._parser = ReportParser()
        
    def load(self, filename, callbackFunction):
        """
        Opens 'filename' and passes each valid Report to 'callbackFunction'. Returns nothing.
        """
        def convert(line):
            report = self._parser.parseString(line)
            if report is not Report.INVALID():
                callbackFunction(report)
            elif self._printErrorMessages:
                print "Could not parse report '%s'" % line
        DataReader.load(self, filename, convert)
    

class LogEntryDataReader(DataReader):
    '''
    Loads log entries (with CSP violation reports and additional data) from files.
    The file format is one JSON-encoded entry per line.
    '''

    def __init__(self, printErrorMessages=False):
        DataReader.__init__(self, printErrorMessages)
        self._parser = LogEntryParser()
        
    def load(self, filename, callbackFunction):
        """
        Opens 'filename' and passes each valid LogEntry to 'callbackFunction'. Returns nothing.
        """
        def convert(line):
            entry = self._parser.parseString(line)
            if entry is not LogEntry.INVALID():
                callbackFunction(entry)
            elif self._printErrorMessages:
                print "Could not parse log entry '%s'" % line
        DataReader.load(self, filename, convert)
        
        
class PolicyDataReader(DataReader):
    '''
    Loads files with policies (one per line).
    '''

    def __init__(self, printErrorMessages=False):
        DataReader.__init__(self, printErrorMessages)
        self._parser = PolicyParser(expandDefaultSrc=False)
        
    def load(self, filename, callbackFunction):
        """
        Opens 'filename' and passes each valid Policy to 'callbackFunction'. Returns nothing.
        """
        def convert(line):
            pol = self._parser.parse(line)
            if pol is not Policy.INVALID():
                callbackFunction(pol)
            elif self._printErrorMessages:
                print "Could not parse policy '%s'" % line
        DataReader.load(self, filename, convert)

