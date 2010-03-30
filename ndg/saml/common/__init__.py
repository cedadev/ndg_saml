"""SAML 2.0 common package

Implementation of SAML 2.0 for NDG Security

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
__date__ = "11/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
from ndg.saml.common.xml import SAMLConstants, QName
 

class SAMLObject(object):
    """Base class for all SAML types"""
    DEFAULT_ELEMENT_LOCAL_NAME = None
    __slots__ = ('__qname',)
    
    def __init__(self,
                 namespaceURI=SAMLConstants.SAML20_NS, 
                 elementLocalName=None, 
                 namespacePrefix=SAMLConstants.SAML20_PREFIX):
        '''@param namespaceURI: the namespace the element is in
        @param elementLocalName: the local name of the XML element this Object 
        represents
        @param namespacePrefix: the prefix for the given namespace
        '''
        if elementLocalName is None:
            elementLocalName = self.__class__.DEFAULT_ELEMENT_LOCAL_NAME
            
        self.__qname = QName(namespaceURI, 
                             elementLocalName, 
                             namespacePrefix)
            
    @property
    def qname(self):
        "Qualified Name for this type"
        return self.__qname
            
    @classmethod
    def fromXML(cls, xmlObject):
        '''Parse from an XML representation into a SAML object
        @type: XML class e.g. ElementTree or 4Suite XML
        @param: XML representation of SAML Object
        @rtype: saml.saml2.common.SAMLObject derived type
        @return: SAML object
        '''
        raise NotImplementedError()
    
    @classmethod
    def toXML(cls, samlObject):
        '''Convert the input SAML object into an XML representation
        @type: saml.saml2.common.SAMLObject derived type
        @param: SAML object
        @rtype: XML class e.g. ElementTree or 4Suite XML
        @return: XML representation of SAML Object
        '''
        raise NotImplementedError()

    def __getstate__(self):
        '''Enable pickling'''
        _dict = {}
        for attrName in SAMLObject.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_SAMLObject" + attrName
                
            try:
                _dict[attrName] = getattr(self, attrName)
            except:
                pass
            
        return _dict
  
    def __setstate__(self, attrDict):
        '''Enable pickling'''
        for attrName, val in attrDict.items():
            setattr(self, attrName, val)
            

class SAMLVersion(object):
    """Version helper class"""
    
    VERSION_10 = (1, 0)
    VERSION_11 = (1, 1)
    VERSION_20 = (2, 0)
    KNOWN_VERSIONS = (VERSION_10, VERSION_11, VERSION_20)
    
    __slots__ = ('__version', )
    
    def __init__(self, version):
        if isinstance(version, basestring):
            self.__version = SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            self.__version = tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version initialiser; got %r" % version)
            
    def __getstate__(self):
        '''Enable pickling'''
        _dict = {}
        for attrName in SAMLVersion.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_SAMLVersion" + attrName
                
            _dict[attrName] = getattr(self, attrName)
            
        return _dict
  
    def __setstate__(self, attrDict):
        '''Enable pickling'''
        for attrName, val in attrDict.items():
            setattr(self, attrName, val)
    
    def __str__(self):
        return ".".join([str(i) for i in self.__version])
    
    def __eq__(self, version):
        """Test for equality against an input version string, tuple or list"""
        if isinstance(version, SAMLVersion):
            return str(self) == str(version)
          
        elif isinstance(version, basestring):
            return self.__version == SAMLVersion.valueOf(version)
        
        elif isinstance(version, (tuple, list)):
            return self.__version == tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
            
    def __ne__(self, version):
        return not self.__eq__(version)
            
    def __gt__(self, version):                
        if isinstance(version, basestring):
            return self.__version > SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            return self.__version > tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
            
    def __lt__(self, version):
        if isinstance(version, basestring):
            return self.__version < SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            return self.__version < tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
            
    def __ge__(self, version):                
        if isinstance(version, basestring):
            return self.__version >= SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            return self.__version >= tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
            
    def __le__(self, version):                
        if isinstance(version, basestring):
            return self.__version <= SAMLVersion.valueOf(version)
        elif isinstance(version, (tuple, list)):
            return self.__version <= tuple(version)
        else:
            raise TypeError("Expecting string, tuple or list type for SAML "
                            "version comparison; got %r" % version)
   
    @staticmethod
    def valueOf(version):
        """Parse input string into version tuple
        @type version: version
        @param version: SAML version
        @rtype: tuple
        @return: SAML version tuple"""
        return tuple([int(i) for i in version.split(".")])