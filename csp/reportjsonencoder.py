'''
JSON encoder for Reports.

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''

import json

class ReportJSONEncoder(json.JSONEncoder):
    '''
    JSON encoder that converts everything to a string that the default
    JSON encoder cannot handle itself.
    '''

    def default(self, obj):
        try:
            return json.JSONEncoder.default(self, obj)
        except TypeError:
            pass
        try:
            return repr(obj)
        except UnicodeEncodeError:
            return "[invalid encoding]"
