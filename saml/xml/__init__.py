"""Implementation of SAML 2.0 for NDG Security - XML package

NERC DataGrid Project

This implementation is adapted from the Java OpenSAML implementation.  The 
copyright and licence information are included here:

Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
__author__ = "P J Kershaw"
__date__ = "23/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
try:
    from datetime import strptime
except ImportError:
    # Allow for Python < 2.5
    from time import strptime as _strptime
    strptime = lambda datetimeStr, format: datetime(*(_strptime(datetimeStr, 
                                                                format)[0:6]))
from datetime import datetime

class XMLObjectError(Exception):
    pass

class XMLObjectParseError(Exception):
    pass

class XMLObject(object):
    """Abstract base class for XML representations of SAML objects"""
    
    def create(self, samlObject):
        """Create an XML representation from the input SAML object
        @type samlObject: SAMLObject
        param samlObject: SAML object to render into XML
        """
        raise NotImplementedError()

    def parse(self, elem):
        """Parse into XML representation
        @type elem: object
        @param elem: XML object - type depends on XML class representation
        @rtype: SAMLObject
        @return: equivalent SAML object
        @raise XMLObjectParsingError: error parsing content into SAML 
        representation
        """
        raise NotImplementedError()
    
    def serialize(self):
        """Serialize the XML object into a string representation
        """
        raise NotImplementedError()
        
        
class IssueInstantXMLObject(XMLObject):
    """Specialisation to enable inclusion of datetime formatting for issue
    instant
    """
    issueInstantFmt = "%Y-%m-%dT%H:%M:%SZ"
    
    @classmethod
    def datetime2Str(cls, dtIssueInstant):
        """Convert issue instant datetime to correct string type for output
        @type dtIssueInstant: datetime.datetime
        @param dtIssueInstant: issue instance as a datetime
        @rtype: basestring
        @return: issue instance as a string
        """
        if not isinstance(dtIssueInstant, datetime):
            raise TypeError("Expecting datetime type for string conversion, "
                            "got %r" % dtIssueInstant)
            
        return dtIssueInstant.strftime(IssueInstantXMLObject.issueInstantFmt)

    @classmethod
    def str2Datetime(cls, issueInstant):
        """Convert issue instant string to datetime type
        @type issueInstant: basestring
        @param issueInstant: issue instance as a string
        @rtype: datetime.datetime
        @return: issue instance as a datetime
        """
        if not isinstance(issueInstant, basestring):
            raise TypeError("Expecting basestring derived type for string "
                            "conversion, got %r" % issueInstant)
            
        return datetime.strptime(issueInstant, 
                                 IssueInstantXMLObject.issueInstantFmt)
        
    
class QName(object):
    """XML Qualified Name""" 

    def __init__(self, namespaceURI, localPart, prefix):
        self.namespaceURI = namespaceURI
        self.localPart = localPart
        self.prefix = prefix
    
    def _getPrefix(self):
        return self.__prefix

    def _setPrefix(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expected string type for "prefix"; got %r' %
                            type(value))
        self.__prefix = value
    
    prefix = property(_getPrefix, _setPrefix, None, "Prefix")

    def _getLocalPart(self):
        return self.__localPart
    
    def _setLocalPart(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expected string type for "localPart"; got %r' %
                            type(value))
        self.__localPart = value
        
    localPart = property(_getLocalPart, _setLocalPart, None, "LocalPart")

    def _getNamespaceURI(self):
        return self.__namespaceURI

    def _setNamespaceURI(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expected string type for "namespaceURI"; got %r' %
                            type(value))
        self.__namespaceURI = value
  
    namespaceURI = property(_getNamespaceURI, _setNamespaceURI, None, 
                            "Namespace URI'")