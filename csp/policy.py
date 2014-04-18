'''
Represents a CSP policy (a list of CSP directives). Report URIs, sandbox, etc. are NOT supported.
Policies can be parsed from strings using PolicyParser.

@author: Tobias Lauinger <toby@ccs.neu.edu>
'''

from directive import Directive, DirectiveParser
from sourceexpression import URISourceExpression
import defaults


class Policy(object):
    """
    A CSP policy that consists of one or more directives. Immutable
    """
    
    _invalid = None
    _defaultSrcDirectiveIfNotSpecified = Directive("default-src", (URISourceExpression(None, "*", None, None),))
    
    def __init__(self, directives):
        """
        Initialises this CSP policy from the given 'directives' list/set/tuple.
        
        'directives': An iterable of Directives. May contain at most one Directive of each type.
        Any Directive that is not regular will be dropped.
        """
        self._hash = None
        self._str = None
        self._isInvalid = False
        # eliminate directives with duplicate type and irregular directives
        onlyRegular = filter(lambda x: x.isRegularDirective(), directives)
        self._directives = frozenset(dict(map(lambda x: (x.getType(), x), onlyRegular)).values())
       
    @staticmethod
    def INVALID():
        """
        Special static singleton Policy representing an invalid policy (could not be parsed).
        """
        if Policy._invalid is None:
            Policy._invalid = Policy(())
            Policy._invalid._isInvalid = True
        return Policy._invalid
    
    def combinedPolicy(self, otherPolicy):
        """
        Returns a new Policy that is the recursive combination of the Directives contained in this 
        Policy and 'otherPolicy' (combining Directives of the same type, and adding Directives
        of a type that is missing in one of the policies). This extends the whitelists and results 
        in a more permissive overall Policy. This method can be used when generating policies from 
        violation reports, but should not be used to enforce multiple policies at the same time 
        (the semantics are different).
        
        If this Policy or 'otherPolicy' is Policy.INVALID(), or if the combination of any of the 
        contained Directives is Directive.INVALID(), this method returns Policy.INVALID(). 
        Because of the special meaning of 'default-src', two policies containing 'default-src' 
        (in one or both policies) can be combined only if 'default-src' is the only directive 
        type in both policies (else Policy.INVALID() is returned).
        """
        if (self == Policy.INVALID()
            or otherPolicy == Policy.INVALID()):
            return Policy.INVALID()
        myDirectives = dict(map(lambda x: (x.getType(), x), self.getDirectives()))
        otherDirectives = dict(map(lambda x: (x.getType(), x), otherPolicy.getDirectives()))
        allDirectiveTypes = set(myDirectives.keys()) | set(otherDirectives.keys())
        if ('default-src' in allDirectiveTypes
            and ((not 'default-src' in myDirectives and len(myDirectives) > 0)
                 or ('default-src' in myDirectives and len(myDirectives) > 1)
                 or (not 'default-src' in otherDirectives and len(otherDirectives) > 0)
                 or ('default-src' in otherDirectives and len(otherDirectives) > 1))):
            return Policy.INVALID()
        combinedDirectives = set([])
        for directiveType in allDirectiveTypes:
            if directiveType not in myDirectives:
                combinedDirectives.add(otherDirectives[directiveType])
            elif directiveType not in otherDirectives:
                combinedDirectives.add(myDirectives[directiveType])
            else:
                combined = myDirectives[directiveType].combinedDirective(otherDirectives[directiveType])
                if combined == Directive.INVALID():
                    return Policy.INVALID()
                else:
                    combinedDirectives.add(combined)
        return Policy(combinedDirectives)
    
    def getDirectives(self):
        """
        Returns a frozen set of all the directives contained in this policy.
        """
        return self._directives # is already immutable
    
    def matches(self, resourceURI, resourceType, protectedDocumentURI, schemePortMappings=defaults.schemePortMappings,
                    defaultSrcTypes=defaults.defaultSrcReplacementDirectiveTypes):
        """
        Returns whether the given resourceURI is allowed under this Policy. Attempts to match 
        
        'resourceURI' is an URI object corresponding to the resource that is attempted to be loaded/executed.
        Can be either one of the special URI.UNSAFE_EVAL() / URI.UNSAFE_INLINE() URIs, or a regular URI.
        In the latter case, escaped characters in the path of the URI should already have been decoded. 
        If 'resourceURI' designates a directory (as opposed to a file), its path must end with a '/'. 
        May not be None.
        
        'resourceType' indicates the type of the 'resourceURI', which is a directive type as
        returned by Directive.getType() (such as 'img-src' or 'script-src' for image and script resources,
        respectively).
        
        'protectedDocumentURI' is the URI of the document in the context of which 'resourceURI' is being 
        attempted to be loaded/executed (the host document). May not be None.
        
        'schemePortMappings': A dictionary with mappings from (lowercase) scheme names to the corresponding
        default port. Will be used if ports are missing in the 'resourceURI' or 'protectedDocumentURI'.
        
        'defaultSrcTypes': A list of (lowercase) directive types to be used for matching, to determine if the
        "default-src" directive can be used if no directive of the needed type is available.
        Example: 'resourceType' is 'script-src', but this Policy contains no 'script-src' Directive.
        If 'defaultSrcTypes' contains 'script-src', the 'default-src' Directive can be used instead of the
        missing 'script-src' Directive, if available.
        
        This implementation requires schemes to be present in both URIs, and either port numbers or a successful
        scheme-to-port-number look up in 'schemePortMappings' for both URIs (otherwise, False is returned).
        For details about the implementation, see http://www.w3.org/TR/2014/WD-CSP11-20140211/#matching
        """
        if self == Policy.INVALID():
            return False
        
        # if directive of resource type is available, use it for matching
        resourceType = resourceType.lower()
        for direct in self._directives:
            if direct.getType() == resourceType:
                return direct.matches(resourceURI, protectedDocumentURI, schemePortMappings)
        
        # check if type of resource admits matching with default-src per CSP 1.1 draft
        if resourceType not in defaultSrcTypes:
            return False
               
        # match with default-src
        # if no default directive is available, assume default-src '*' according to # http://www.w3.org/TR/2014/WD-CSP11-20140211/#default-src
        for direct in self._directives:
            if direct.getType() == "default-src":
                return direct.matches(resourceURI, protectedDocumentURI, schemePortMappings)
        return Policy._defaultSrcDirectiveIfNotSpecified.matches(resourceURI, protectedDocumentURI, schemePortMappings)
        
    def withoutPaths(self, schemeOnly=defaults.schemeOnly):
        """
        Returns a copy of this Policy that has the path components removed from all URISourceExpressions
        in the contained Directives.
        
        'schemeOnly' is a list of scheme names. If the scheme of any source expression is contained
        in this list, not only the path will be removed, but the host and port, too. This is useful
        for data or chrome-extension URIs, for example.
        """
        if self == Policy.INVALID():
            return self
        pathsRemoved = []
        for direct in self._directives:
            pathsRemoved.append(direct.withoutPaths(schemeOnly))
        return Policy(pathsRemoved)
    
    def asBasicPolicies(self):
        """
        Returns a set of Policies that contain each exactly one Directive with exactly one SourceExpression.
        'Decomposes' this Policy into basic Policies and Directives.
        Returns the empty set if this policy is invalid.
        """
        if self == Policy.INVALID():
            return set([])
        if len(self._directives) == 0:
            return frozenset((self,))
        policies = set([])
        for direct in self._directives:
            for bDirect in direct.asBasicDirectives():
                policies.add(Policy((bDirect,)))
        return policies
    
    def compareTo(self, otherPolicy):
        """
        Compares this Policy to 'otherPolicy' and returns three sets of basic Policies (that is, Policies with
        exactly one Directive and one SourceExpression): (common basic policies, basic policies only in 'self',
        basic policies only in 'otherPolicy'). If this Policy or 'otherPolicy' is INVALID(), returns three
        empty sets.
        """
        if self == Policy.INVALID() or otherPolicy == Policy.INVALID():
            return (set([]), set([]), set([]))
        selfBasic = self.asBasicPolicies()
        otherBasic = otherPolicy.asBasicPolicies()
        common = selfBasic & otherBasic
        onlySelf = selfBasic - common
        onlyOther = otherBasic - common
        return (common, onlySelf, onlyOther)
    
    def isBasicPolicy(self):
        """
        Returns if this Policy is basic. That is, whether it consists of exactly one Directive, and whether
        that Directive is basic.
        """
        if self == Policy.INVALID():
            return False
        if len(self._directives) != 1:
            return False
        return self._directives.__iter__().next().isBasicDirective()
    
    def isBasicNonePolicy(self):
        """
        Returns if this Policy is basic, and has an empty whitelisted resource list in the Directive.
        """
        if self == Policy.INVALID():
            return False
        if len(self._directives) != 1:
            return False
        direct = self._directives.__iter__().next()
        return len(direct.getWhitelistedSourceExpressions()) == 0
    
    def hasDefaultDirective(self):
        """
        Returns whether this Policy has a 'default-src' Directive.
        """
        if self == Policy.INVALID():
            return False
        for direct in self._directives:
            if direct.getType() == "default-src":
                return True
        return False
    
    def __repr__(self):
        """
        Returns a full representation of this Policy. Equivalent to __str__().
        """
        return str(self)
    
    def __str__(self):
        """
        Returns a string representation of this policy (directives in sorted order).
        """
        if self._str is None:
            if self == Policy.INVALID():
                self._str = "[invalid]"
            else:
                stringPolicyList = map(lambda x: str(x), self._directives)
                stringPolicyList.sort()
                self._str = ("; ".join(stringPolicyList))
        return self._str
    
    def __eq__(self, other):
        """
        Returns whether the two policies have the elements. This is NOT the same as checking whether
        they have the same effect.
        """
        if type(other) != Policy:
            return False
        return (self._isInvalid == other._isInvalid
                and self._directives == other._directives)
    
    def __hash__(self):
        """
        Returns a hash value for this object that is guaranteed to be the same for two objects
        that are equal (the opposite is not necessarily true).
        """
        if self._hash is None:
            self._hash = hash(self._directives) ^ hash(self._isInvalid)
        return self._hash
    
    
class PolicyParser(object):
    """
    Pre-configured object that parses strings into Policies.
    """
    
    def __init__(self, 
                 typeTranslations=defaults.directiveTypeTranslations, 
                 allowedTypes=defaults.allowedDirectiveTypes,
                 ignoredTypes=defaults.ignoredDirectiveTypes,
                 knownSchemes=defaults.supportedSchemes,
                 strict=True,
                 expandDefaultSrc=True,
                 defaultSrcTypes=defaults.defaultSrcReplacementDirectiveTypes):
        """
        Creates a new DirectiveParser object configured with the following parameters:
        'typeTranslations': For parsing directives. A map from directive types to another directive type
        (all lowercase). Used to convert old names to the new name.
        'allowedTypes': For parsing directives. A list of directive types that are allowed. All lowercase.
        (Parsing other types will result in Directive.INVALID().)
        'ignoredTypes': Directives of this type will be ignored when parsing a policy. Usually, this includes
        directives without whitelisted source expressions, such as "sandbox" or "report-uri". (These have a 
        special format that is not currently supported.) All lowercase.
        'knownSchemes': For parsing source expressions. A list of all schemes that are supported. (Others may
        result in errors or Directive.INVALID().) All lowercase.
        'strict': if set to True, parsing errors of the policy or any directive or source expressions contained 
        therein will be fixed by ignoring the invalid portion. Otherwise, any parsing error will result in 
        Policy.INVALID().
        'expandDefaultSrc': If true, will "expand" any occurrence of "default-src" directives into the elementary
        types defined in 'defaultSrcTypes' (such as "script-src" etc.). This preserves the semantics of the policy. 
        That is, if an elementary type directive already exists in the policy, it will NOT be replaced. 
        (This is the behaviour for interpreting policies according to the CSP 1.1 draft.)
        'defaultSrcTypes': A list of (lowercase) directive types to be used with 'expandDefaultSrc'.
        """
        self._allowedTypes = allowedTypes
        self._ignoredTypes = ignoredTypes
        self._directiveParser = DirectiveParser(typeTranslations, allowedTypes, knownSchemes, strict)
        self._strict = strict
        self._expandDefaultSrc = expandDefaultSrc
        self._defaultSrcTypes = defaultSrcTypes
    
    def parse(self, stringPolicy):
        """
        Parses the given 'stringPolicy' according to the parameters set in the constructor of this PolicyParser 
        and returns a Policy object. If 'stringPolicy' cannot be parsed because it is syntactically invalid (or empty),
        Policy.INVALID() will be returned. (A policy cannot consist of only whitespace.)

        Depending on the configuration of this PolicyParser object, may perform internal translation of the type 
        and filter certain directive types.
        """
        directiveStrings = stringPolicy.split(";")
        directives = {} # type -> Directive
        for directiveString in directiveStrings:
            if self._isIgnoredDirectiveType(directiveString):
                continue
            directive = self._directiveParser.parse(directiveString)
            if directive == Directive.INVALID():
                if self._strict:
                    return Policy.INVALID()
                else:
                    continue
            if directive.getType() in directives:
                continue # could emit a warning here; the standard says to ignore subsequent definitions
            directives[directive.getType()] = directive
        if self._expandDefaultSrc:
            self._normaliseDirectivesMap(directives)
        if len(directives) == 0:
            return Policy.INVALID()
        return Policy(directives.values())
    
    def _isIgnoredDirectiveType(self, directiveStr):
        """
        Returns if the directiveStr begins with a type that is in the list of ignored directive types
        (usually, this would be sandbox, report-uri, etc. directives).
        """
        directiveStr = directiveStr.strip().lower()
        for ignoredType in self._ignoredTypes:
            if directiveStr[:len(ignoredType)+1] == ignoredType + " ":
                return True
        return False
    
    def _normaliseDirectivesMap(self, directivesMap):
        """
        Removes any 'default-src' directive and expands it to all basic directive types that are not yet 
        specified (in place).
        """
        if not "default-src" in directivesMap:
            return
        defaultDirective = directivesMap['default-src']
        for otherType in self._defaultSrcTypes:
            if not otherType in directivesMap:
                directivesMap[otherType] = Directive(otherType, defaultDirective.getWhitelistedSourceExpressions())
        del directivesMap["default-src"]

