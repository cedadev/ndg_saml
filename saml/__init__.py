"""Implementation of SAML 2.0 for NDG Security

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
__date__ = "22/07/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import logging
log = logging.getLogger(__name__)

# Time module for use with validity times
from time import strftime, strptime
from datetime import datetime
   
# TODO: remove ElementTree dependency - package should XML implementation
# independent
from saml.utils import TypedList
from saml.xml import QName
from saml.common.xml import SAMLConstants, XMLConstants
from saml.saml2.core import AttributeValue
    
    
class XSStringAttributeValue(AttributeValue):

    # Local name of the XSI type
    TYPE_LOCAL_NAME = "string"
        
    # QName of the XSI type
    TYPE_NAME = QName(XMLConstants.XSD_NS, 
                      TYPE_LOCAL_NAME, 
                      XMLConstants.XSD_PREFIX)
  
    def __init__(self):
        self.__value = None
        
    def _getValue(self):
        return self.__value
        
    def _setValue(self, value):
        if not isinstance(value, basestring):
            raise TypeError("Input must be a basestring derived type, got %r" %
                            value.__class__)
            
        self.__value = value

    value = property(fget=_getValue, fset=_setValue, doc="string value")  
    

class XSGroupRoleAttributeValue(AttributeValue): 
    '''ESG Specific Group/Role attribute value.  ESG attribute permissions are
    organised into group/role pairs
    '''
    DEFAULT_NS = "http://www.esg.org"
    DEFAULT_PREFIX = "esg"
    TYPE_LOCAL_NAME = "groupRole"
    
    GROUP_ATTRIB_NAME = "group"
    ROLE_ATTRIB_NAME = "role"
    
    # QName of the XSI type
    TYPE_NAME = QName(DEFAULT_NS, 
                      TYPE_LOCAL_NAME, 
                      DEFAULT_PREFIX)
     
    def __init__(self, 
                 namespaceURI=DEFAULT_NS, 
                 elementLocalName=TYPE_LOCAL_NAME, 
                 namespacePrefix=DEFAULT_PREFIX):
        '''@param namespaceURI: the namespace the element is in
        @param elementLocalName: the local name of the XML element this Object 
        represents
        @param namespacePrefix: the prefix for the given namespace'''
        self.__namespaceURI = namespaceURI
        self.__elementLocalName = elementLocalName
        self.__namespacePrefix = namespacePrefix
        self.__group = None
        self.__role = None        

    def _getNamespaceURI(self):
        return self.__namespaceURI

    def _setNamespaceURI(self, value):
        if not isinstance(value, basestring):
            raise TypeError("Expecting %r type for namespaceURI got %r" %
                            (basestring, value.__class__))
        self.__namespaceURI = value

    def _getElementLocalName(self):
        return self.__elementLocalName

    def _setElementLocalName(self, value):
        if not isinstance(value, basestring):
            raise TypeError("Expecting %r type for elementLocalName got %r" %
                            (basestring, value.__class__))
        self.__elementLocalName = value

    def _getNamespacePrefix(self):
        return self.__namespacePrefix

    def _setNamespacePrefix(self, value):
        if not isinstance(value, basestring):
            raise TypeError("Expecting %r type for namespacePrefix got %r" %
                            (basestring, value.__class__))
        self.__namespacePrefix = value

    namespaceURI = property(fget=_getNamespaceURI, 
                            fset=_setNamespaceURI, 
                            doc="the namespace the element is in")

    elementLocalName = property(fget=_getElementLocalName, 
                                fset=_setElementLocalName, 
                                doc="the local name of the XML element this "
                                    "Object represents")

    namespacePrefix = property(fget=_getNamespacePrefix, 
                               fset=_setNamespacePrefix, 
                               doc="the prefix for the given namespace")

    def _getGroup(self):
        return self.__group
     
    def _setGroup(self, group): 
        self.__group = group
     
    group = property(fget=_getGroup, fset=_setGroup)
     
    def _getRole(self):
        return self.__role
     
    def _setRole(self, role):
        self.__role = role
     
    role = property(fget=_getRole, fset=_setRole)

    def getOrderedChildren(self):
        # no children
        return None
