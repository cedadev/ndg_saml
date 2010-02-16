"""SAML 2.0 core module

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
from datetime import datetime
from urlparse import urlsplit, urlunsplit
import urllib

from saml.common import SAMLObject, SAMLVersion
from saml.common.xml import SAMLConstants, QName
from saml.utils import TypedList


class Attribute(SAMLObject):
    '''SAML 2.0 Core Attribute.'''
    
    # Local name of the Attribute element. 
    DEFAULT_ELEMENT_LOCAL_NAME = "Attribute"

    # Default element name. 
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type. 
    TYPE_LOCAL_NAME = "AttributeType"

    # QName of the XSI type. 
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    # Name of the Name attribute. 
    NAME_ATTRIB_NAME = "Name"

    # Name for the NameFormat attribute. 
    NAME_FORMAT_ATTRIB_NAME = "NameFormat"

    # Name of the FriendlyName attribute. 
    FRIENDLY_NAME_ATTRIB_NAME = "FriendlyName"

    # Unspecified attribute format ID. 
    UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"

    # URI reference attribute format ID. 
    URI_REFERENCE = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

    # Basic attribute format ID. 
    BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

    __slots__ = (
        '__name',
        '__nameFormat',
        '__friendlyName',
        '__attributeValues'
    )
    
    def __init__(self, **kw):
        """Initialise Attribute Class attributes"""
        super(Attribute, self).__init__(**kw)
        
        self.__name = None
        self.__nameFormat = None
        self.__friendlyName = None
        self.__attributeValues = []

    def _get_name(self):
        return self.__name
    
    def _set_name(self, name):
        if not isinstance(name, basestring):
            raise TypeError("Expecting basestring type for name, got %r"% name)
        
        self.__name = name
        
    name = property(fget=_get_name,
                    fset=_set_name,
                    doc="name of this attribute")
    
    def _get_nameFormat(self):
        return self.__nameFormat
    
    def _set_nameFormat(self, nameFormat):
        if not isinstance(nameFormat, basestring):
            raise TypeError("Expecting basestring type for nameFormat, got %r"
                            % nameFormat)
            
        self.__nameFormat = nameFormat
        
    nameFormat = property(fget=_get_nameFormat,
                          fset=_set_nameFormat,
                          doc="Get the name format of this attribute.")
    
    def _get_friendlyName(self):
        return self.__friendlyName
    
    def _set_friendlyName(self, friendlyName):
        if not isinstance(friendlyName, basestring):
            raise TypeError("Expecting basestring type for friendlyName, got "
                            "%r" % friendlyName)
            
        self.__friendlyName = friendlyName
        
    friendlyName = property(fget=_get_friendlyName,
                            fset=_set_friendlyName,
                            doc="the friendly name of this attribute.")
    
    def _get_attributeValues(self):
        return self.__attributeValues
    
    def _set_attributeValues(self, attributeValues):
        if not isinstance(attributeValues, (list, tuple)):
            raise TypeError("Expecting basestring type for attributeValues, "
                            "got %r" % attributeValues)
            
        self.__attributeValues = attributeValues
        
    attributeValues = property(fget=_get_attributeValues,
                               fset=_set_attributeValues,
                               doc="the list of attribute values for this "
                               "attribute.")


class Statement(SAMLObject):
    '''SAML 2.0 Core Statement.  Abstract base class which all statement 
    types must implement.'''
    __slots__ = ()
    
    # Element local name
    DEFAULT_ELEMENT_LOCAL_NAME = "Statement"

    # Default element name
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type
    TYPE_LOCAL_NAME = "StatementAbstractType"

    # QName of the XSI type
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)
    
            
class AttributeStatement(Statement):
    '''SAML 2.0 Core AttributeStatement'''
    __slots__ = ('__attributes', '__encryptedAttributes')
    
    def __init__(self, **kw):
        super(AttributeStatement, self).__init__(**kw)
        
        self.__attributes = TypedList(Attribute)
        self.__encryptedAttributes = TypedList(Attribute)

    # Element local name
    DEFAULT_ELEMENT_LOCAL_NAME = "AttributeStatement"
    
    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME, 
                                 SAMLConstants.SAML20_PREFIX)
    
    # Local name of the XSI type. 
    TYPE_LOCAL_NAME = "AttributeStatementType" 
        
    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME, 
                      SAMLConstants.SAML20_PREFIX)

    def _get_attributes(self):
        '''@return: the attributes expressed in this statement
        '''
        return self.__attributes

    attributes = property(fget=_get_attributes)
    
    def _get_encryptedAttributes(self):
       '''@return: the encrypted attribtues expressed in this statement
       '''
       return self.__encryptedAttributes
   
    encryptedAttributes = property(fget=_get_encryptedAttributes)


class AuthnStatement(Statement):
    '''SAML 2.0 Core AuthnStatement.  Currently implemented in abstract form
    only
    '''

    # Element local name
    DEFAULT_ELEMENT_LOCAL_NAME = "AuthnStatement"

    # Default element name
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type
    TYPE_LOCAL_NAME = "AuthnStatementType"

    # QName of the XSI type
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    # AuthnInstant attribute name
    AUTHN_INSTANT_ATTRIB_NAME = "AuthnInstant"

    # SessionIndex attribute name
    SESSION_INDEX_ATTRIB_NAME = "SessionIndex"

    # SessionNoOnOrAfter attribute name
    SESSION_NOT_ON_OR_AFTER_ATTRIB_NAME = "SessionNotOnOrAfter"

    def _getAuthnInstant(self):
        '''Gets the time when the authentication took place.
        
        @return: the time when the authentication took place
        '''
        raise NotImplementedError()

    def _setAuthnInstant(self, value):
        '''Sets the time when the authentication took place.
        
        @param value: the time when the authentication took place
        '''
        raise NotImplementedError()

    def _getSessionIndex(self):
        '''Get the session index between the principal and the authenticating 
        authority.
        
        @return: the session index between the principal and the authenticating 
        authority
        '''
        raise NotImplementedError()

    def _setSessionIndex(self, value):
        '''Sets the session index between the principal and the authenticating 
        authority.
        
        @param value: the session index between the principal and the 
        authenticating authority
        '''
        raise NotImplementedError()

    def _getSessionNotOnOrAfter(self):
        '''Get the time when the session between the principal and the SAML 
        authority ends.
        
        @return: the time when the session between the principal and the SAML 
        authority ends
        '''
        raise NotImplementedError()

    def _setSessionNotOnOrAfter(self, value):
        '''Set the time when the session between the principal and the SAML 
        authority ends.
        
        @param value: the time when the session between the 
        principal and the SAML authority ends
        '''
        raise NotImplementedError()

    def _getSubjectLocality(self):
        '''Get the DNS domain and IP address of the system where the principal 
        was authenticated.
        
        @return: the DNS domain and IP address of the system where the principal
        was authenticated
        '''
        raise NotImplementedError()

    def _setSubjectLocality(self, value):
        '''Set the DNS domain and IP address of the system where the principal 
        was authenticated.
        
        @param value: the DNS domain and IP address of the system where 
        the principal was authenticated
        '''
        raise NotImplementedError()

    def _getAuthnContext(self):
        '''Gets the context used to authenticate the subject.
        
        @return: the context used to authenticate the subject
        '''
        raise NotImplementedError()

    def _setAuthnContext(self, value):
        '''Sets the context used to authenticate the subject.
        
        @param value: the context used to authenticate the subject
        '''
        raise NotImplementedError()


class DecisionType(object):
    """Define decision types for the authorisation decisions"""
    
    # "Permit" decision type
    PERMIT_STR = "Permit"
    
    # "Deny" decision type
    DENY_STR = "Deny"
    
    # "Indeterminate" decision type
    INDETERMINATE_STR = "Indeterminate"
        
    TYPES = (PERMIT_STR, DENY_STR, INDETERMINATE_STR)
    
    __slots__ = ('__value',)
    
    def __init__(self, decisionType):
        self.__value = None
        self.value = decisionType

    def _setValue(self, value):
        if isinstance(value, DecisionType):
            # Cast to string
            value = str(value)
            
        elif not isinstance(value, basestring):
            raise TypeError('Expecting string or DecisionType instance for '
                            '"value" attribute; got %r instead' % type(value))
            
        if value not in self.__class__.TYPES:
            raise AttributeError('Permissable decision types are %r; got '
                                 '%r instead' % (DecisionType.TYPES, value))
        self.__value = value
        
    def _getValue(self):
        return self.__value
    
    value = property(fget=_getValue, fset=_setValue, doc="Decision value")
    
    def __str__(self):
        return self.__value

    def __eq__(self, decision):
        return self.__value == decision.value


class PermitDecisionType(DecisionType):
    """Permit authorisation Decision"""
    def __init__(self):
        super(PermitDecisionType, self).__init__(DecisionType.PERMIT_STR)
        
    def _setValue(self):  
        raise AttributeError("can't set attribute")


class DenyDecisionType(DecisionType):
    """Deny authorisation Decision"""
    def __init__(self):
        super(DenyDecisionType, self).__init__(DecisionType.DENY_STR)
        
    def _setValue(self, value):  
        raise AttributeError("can't set attribute")


class IndeterminateDecisionType(DecisionType):
    """Indeterminate authorisation Decision"""
    def __init__(self):
        super(IndeterminateDecisionType, self).__init__(
                                            DecisionType.INDETERMINATE_STR)
        
    def _setValue(self, value):  
        raise AttributeError("can't set attribute")

# Add instances of each for convenience
DecisionType.PERMIT = PermitDecisionType()
DecisionType.DENY = DenyDecisionType()
DecisionType.INDETERMINATE = IndeterminateDecisionType()


class AuthzDecisionStatement(Statement):
    '''SAML 2.0 Core AuthzDecisionStatement.  Currently implemented in abstract
    form only'''
    
    # Element local name
    DEFAULT_ELEMENT_LOCAL_NAME = "AuthzDecisionStatement"

    # Default element name
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type
    TYPE_LOCAL_NAME = "AuthzDecisionStatementType"

    # QName of the XSI type
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    # Resource attribute name
    RESOURCE_ATTRIB_NAME = "Resource"

    # Decision attribute name
    DECISION_ATTRIB_NAME = "Decision"
    
    def __init__(self, 
                 normalizeResource=True, 
                 safeNormalizationChars='/%',
                 **kw):
        '''Create new authorisation decision statement
        '''
        super(AuthzDecisionStatement, self).__init__(**kw)

        # Resource attribute value. 
        self.__resource = None  
        
        self.__decision = DecisionType.INDETERMINATE   
        self.__actions = TypedList(Action)
        self.__evidence = None
        
        # Tuning for normalization of resource URIs in property set method
        self.normalizeResource = normalizeResource
        self.safeNormalizationChars = safeNormalizationChars

    def _getNormalizeResource(self):
        return self.__normalizeResource

    def _setNormalizeResource(self, value):
        if not isinstance(value, bool):
            raise TypeError('Expecting bool type for "normalizeResource" '
                            'attribute; got %r instead' % type(value))
            
        self.__normalizeResource = value

    normalizeResource = property(_getNormalizeResource, 
                                 _setNormalizeResource, 
                                 doc="Flag to normalize new resource value "
                                     "assigned to the \"resource\" property.  "
                                     "The setting only applies for URIs "
                                     'beginning with "http://" or "https://"')

    def _getSafeNormalizationChars(self):
        return self.__safeNormalizationChars

    def _setSafeNormalizationChars(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "normalizeResource" '
                            'attribute; got %r instead' % type(value))
            
        self.__safeNormalizationChars = value

    safeNormalizationChars = property(_getSafeNormalizationChars, 
                                      _setSafeNormalizationChars, 
                                      doc="String containing a list of "
                                          "characters that should not be "
                                          "converted when Normalizing the "
                                          "resource URI.  These are passed to "
                                          "urllib.quote when the resource "
                                          "property is set.  The default "
                                          "characters are '/%'")

    def _getResource(self):
        '''Gets the Resource attrib value of this query.

        @return: the Resource attrib value of this query'''
        return self.__resource
    
    def _setResource(self, value):
        '''Sets the Resource attrib value of this query normalizing the path
        component, removing spurious port numbers (80 for HTTP and 443 for 
        HTTPS) and converting the host component to lower case.
        
        @param value: the new Resource attrib value of this query'''
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "resource" attribute; '
                            'got %r instead' % type(value))
        
        if (self.normalizeResource and 
            value.startswith('http://') or value.startswith('https://')):
            # Normalise the path, set the host name to lower case and remove 
            # port redundant numbers 80 and 443
            splitResult = urlsplit(value)
            uriComponents = list(splitResult)
            
            # hostname attribute is lowercase
            uriComponents[1] = splitResult.hostname
            
            if splitResult.port is not None:
                isHttpWithStdPort = (splitResult.port == 80 and 
                                     splitResult.scheme == 'http')
                
                isHttpsWithStdPort = (splitResult.port == 443 and
                                      splitResult.scheme == 'https')
                
                if not isHttpWithStdPort and not isHttpsWithStdPort:
                    uriComponents[1] += ":%d" % splitResult.port
            
            uriComponents[2] = urllib.quote(splitResult.path, 
                                            self.safeNormalizationChars)
            
            self.__resource = urlunsplit(uriComponents)
        else:
            self.__resource = value
    
    resource = property(fget=_getResource, fset=_setResource,
                        doc="Resource for which authorisation was requested")

    def _getDecision(self):
        '''
        Gets the decision of the authorization request.
        
        @return: the decision of the authorization request
        '''
        return self.__decision

    def _setDecision(self, value):
        '''
        Sets the decision of the authorization request.
        
        @param value: the decision of the authorization request
        '''
        if not isinstance(value, DecisionType):
            raise TypeError('Expecting %r type for "decision" attribute; '
                            'got %r instead' % (DecisionType, type(value)))
        self.__decision = value

    decision = property(_getDecision, _setDecision, 
                        doc="Authorization decision as a DecisionType instance")
    
    @property
    def actions(self):
        '''The actions for which authorisation is requested
        
        @return: the Actions of this statement'''
        return self.__actions
   
    def _getEvidence(self):
        '''Gets the Evidence of this statement.

        @return: the Evidence of this statement'''
        return self.__evidence

    def _setEvidence(self, value):
        '''Sets the Evidence of this query.
        @param newEvidence: the new Evidence of this statement'''  
        if not isinstance(value, Evidence):
            raise TypeError('Expecting Evidence type for "evidence" '
                            'attribute; got %r' % type(value))

        self.__evidence = value  

    evidence = property(fget=_getEvidence, fset=_setEvidence, 
                        doc="A set of assertions which the Authority may use "
                            "to base its authorisation decision on")
    
    def getOrderedChildren(self):
        children = []

        superChildren = super(AuthzDecisionStatement, self).getOrderedChildren()
        if superChildren:
            children.extend(superChildren)

        children.extend(self.__actions)
        
        if self.__evidence is not None:
            children.extend(self.__evidence)

        if len(children) == 0:
            return None

        return tuple(children)
        

class Subject(SAMLObject):
    '''Concrete implementation of @link org.opensaml.saml2.core.Subject.'''
    
    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "Subject"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "SubjectType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)
    __slots__ = (
        '__qname',
        '__baseID',
        '__nameID',
        '__encryptedID',
        '__subjectConfirmations'
    )
    
    def __init__(self, **kw):
        super(Subject, self).__init__(**kw)
        
        # BaseID child element.
        self.__baseID = None
    
        # NameID child element.
        self.__nameID = None
    
        # EncryptedID child element.
        self.__encryptedID = None
    
        # Subject Confirmations of the Subject.
        self.__subjectConfirmations = []
    
    def _getBaseID(self): 
        return self.__baseID

    def _setBaseID(self, value):
        if not isinstance(value, basestring):
            raise TypeError("Expecting %r type for \"baseID\" got %r" %
                            (basestring, value.__class__))
        self.__baseID = value

    baseID = property(fget=_getBaseID, 
                      fset=_setBaseID, 
                      doc="Base identifier")
      
    def _getNameID(self):
        return self.__nameID
    
    def _setNameID(self, value):
        if not isinstance(value, NameID):
            raise TypeError("Expecting %r type for \"nameID\" got %r" %
                            (NameID, type(value)))
        self.__nameID = value

    nameID = property(fget=_getNameID, 
                      fset=_setNameID, 
                      doc="Name identifier")
    
    def _getEncryptedID(self):
        return self.__encryptedID
    
    def _setEncryptedID(self, value): 
        self.__encryptedID = value

    encryptedID = property(fget=_getEncryptedID, 
                           fset=_setEncryptedID, 
                           doc="EncryptedID's Docstring")
    
    def _getSubjectConfirmations(self): 
        return self.__subjectConfirmations

    subjectConfirmations = property(fget=_getSubjectConfirmations, 
                                    doc="Subject Confirmations")    
    
    def getOrderedChildren(self): 
        children = []

        if self.baseID is not None:
            children.append(self.baseID)
        
        if self.nameID is not None: 
            children.append(self.nameID)
        
        if self.encryptedID is not None: 
            children.append(self.encryptedID)
        
        children += self.subjectConfirmations

        return tuple(children)


class AbstractNameIDType(SAMLObject):
    '''Abstract implementation of NameIDType'''

    # SPNameQualifier attribute name.
    SP_NAME_QUALIFIER_ATTRIB_NAME = "SPNameQualifier"

    # Format attribute name.
    FORMAT_ATTRIB_NAME = "Format"

    # SPProviderID attribute name.
    SPPROVIDED_ID_ATTRIB_NAME = "SPProvidedID"

    # URI for unspecified name format.
    UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

    # URI for email name format.
    EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    # URI for X509 subject name format.
    X509_SUBJECT = "urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName"

    # URI for windows domain qualified name name format.
    WIN_DOMAIN_QUALIFIED = \
        "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"

    # URI for kerberos name format.
    KERBEROS = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"

    # URI for SAML entity name format.
    ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"

    # URI for persistent name format.
    PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

    # URI for transient name format.
    TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

    # Special URI used by NameIDPolicy to indicate a NameID should be encrypted
    ENCRYPTED = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"
    
    __slots__ = (
        '__qname',
        '__name',
        '__nameQualifier',
        '__spNameQualifier',
        '__format',
        '__spProvidedID',
        '__value'
    )
    
    def __init__(self, namespaceURI, elementLocalName, namespacePrefix): 
        '''@param namespaceURI: the namespace the element is in
        @param elementLocalName: the local name of the XML element this Object 
        represents
        @param namespacePrefix: the prefix for the given namespace
        '''
        self.__qname = QName(namespaceURI, elementLocalName, namespacePrefix)
    
        # Name of the Name ID.
        self.__name = None
        
        # Name Qualifier of the Name ID.
        self.__nameQualifier = None
    
        # SP Name Qualifier of the Name ID.
        self.__spNameQualifier = None
    
        # Format of the Name ID.
        self.__format = None
    
        # SP ProvidedID of the NameID.
        self.__spProvidedID = None

        self.__value = None
        
    def _getQName(self):
        return self.__qname
        
    def _setQName(self, value):
        if not isinstance(value, QName):
            raise TypeError("\"qname\" must be a %r derived type, "
                            "got %r" % (QName, type(value)))
            
        self.__qname = value

    qname = property(fget=_getQName, fset=_setQName, doc="qualified name")
             
    def _getValue(self):
        return self.__value
        
    def _setValue(self, value):
        if not isinstance(value, basestring):
            raise TypeError("\"value\" must be a basestring derived type, "
                            "got %r" % value.__class__)
            
        self.__value = value

    value = property(fget=_getValue, fset=_setValue, doc="string value")  
    
    def _getNameQualifier(self): 
        return self.__nameQualifier
    
    def _setNameQualifier(self, value): 
        self.__nameQualifier = value

    nameQualifier = property(fget=_getNameQualifier, 
                             fset=_setNameQualifier, 
                             doc="Name qualifier")    

    def _getSPNameQualifier(self): 
        return self.__spNameQualifier
    
    def _setSPNameQualifier(self, value): 
        self.__spNameQualifier = value

    spNameQualifier = property(fget=_getSPNameQualifier, 
                               fset=_setSPNameQualifier, 
                               doc="SP Name qualifier")    
    
    def _getFormat(self):
        return self.__format
        
    def _setFormat(self, format):
        if not isinstance(format, basestring):
            raise TypeError("\"format\" must be a basestring derived type, "
                            "got %r" % format.__class__)
            
        self.__format = format

    format = property(fget=_getFormat, fset=_setFormat, doc="Name format")  
    
    def _getSPProvidedID(self): 
        return self.__spProvidedID
    
    def _setSPProvidedID(self, value): 
        self.__spProvidedID = value

    spProvidedID = property(fget=_getSPProvidedID, fset=_setSPProvidedID, 
                            doc="SP Provided Identifier")  
    
    def getOrderedChildren(self): 
        raise NotImplementedError()

   
class Issuer(AbstractNameIDType):
    """SAML 2.0 Core Issuer type"""
    
    # Element local name. 
    DEFAULT_ELEMENT_LOCAL_NAME = "Issuer"

    # Default element name. 
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type. 
    TYPE_LOCAL_NAME = "IssuerType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX) 
    
    def __init__(self, 
                 namespaceURI=SAMLConstants.SAML20_NS, 
                 localPart=DEFAULT_ELEMENT_LOCAL_NAME, 
                 namespacePrefix=SAMLConstants.SAML20_PREFIX):
        super(Issuer, self).__init__(namespaceURI,
                                     localPart,
                                     namespacePrefix)

     
class NameID(AbstractNameIDType):
    '''SAML 2.0 Core NameID'''
    # Element local name. 
    DEFAULT_ELEMENT_LOCAL_NAME = "NameID"

    # Default element name. 
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type. 
    TYPE_LOCAL_NAME = "NameIDType"

    # QName of the XSI type. 
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)
    
    __slots__ = ()
    
    def __init__(self, 
                 namespaceURI=SAMLConstants.SAML20_NS, 
                 localPart=DEFAULT_ELEMENT_LOCAL_NAME, 
                 namespacePrefix=SAMLConstants.SAML20_PREFIX):
        super(NameID, self).__init__(namespaceURI,
                                     localPart,
                                     namespacePrefix)


class Conditions(SAMLObject): 
    '''SAML 2.0 Core Conditions.'''
    
    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "Conditions"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "ConditionsType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    # NotBefore attribute name.
    NOT_BEFORE_ATTRIB_NAME = "NotBefore"

    # NotOnOrAfter attribute name.
    NOT_ON_OR_AFTER_ATTRIB_NAME = "NotOnOrAfter"

    __slots__ = (
        '__conditions',
        '__notBefore',
        '__notOnOrAfter'
    )
    
    def __init__(self):
        
        # A Condition.
        self.__conditions = []
    
        # Not Before conditions.
        self.__notBefore = None
    
        # Not On Or After conditions.
        self.__notOnOrAfter = None

    def _getNotBefore(self):
        '''Get the date/time before which the assertion is invalid.
        
        @return: the date/time before which the assertion is invalid'''
        return self.__notBefore
    
    def _setNotBefore(self, value):
        '''Sets the date/time before which the assertion is invalid.
        
        @param value: the date/time before which the assertion is invalid
        '''
        if not isinstance(value, datetime):
            raise TypeError('Expecting "datetime" type for "notBefore", '
                            'got %r' % type(value))
        self.__notBefore = value

    def _getNotOnOrAfter(self):
        '''Gets the date/time on, or after, which the assertion is invalid.
        
        @return: the date/time on, or after, which the assertion is invalid'
        '''
        return self.__notOnOrAfter
    
    def _setNotOnOrAfter(self, value):
        '''Sets the date/time on, or after, which the assertion is invalid.
        
        @param value: the date/time on, or after, which the assertion 
        is invalid
        '''
        if not isinstance(value, datetime):
            raise TypeError('Expecting "datetime" type for "notOnOrAfter", '
                            'got %r' % type(value))
        self.__notOnOrAfter = value  

    notBefore = property(_getNotBefore, _setNotBefore, 
                         doc="Not before time restriction")

    notOnOrAfter = property(_getNotOnOrAfter, _setNotOnOrAfter, 
                            doc="Not on or after time restriction")

    @property
    def conditions(self):
        '''All the conditions on the assertion.
        
        @return: all the conditions on the assertion
        '''
        return self.__conditions
    
    def _getAudienceRestrictions(self):
        '''Gets the audience restriction conditions for the assertion.
        
        @return: the audience restriction conditions for the assertion
        '''
        raise NotImplementedError()

    def _getOneTimeUse(self):
        '''Gets the OneTimeUse condition for the assertion.
        
        @return: the OneTimeUse condition for the assertion
        '''
        raise NotImplementedError()

    def _getProxyRestriction(self):    
        '''Gets the ProxyRestriction condition for the assertion.
        
        @return: the ProxyRestriction condition for the assertion
        '''
        raise NotImplementedError()
    
    
class Advice(SAMLObject):
    '''SAML 2.0 Core Advice.
    '''

    # Element local name
    DEFAULT_ELEMENT_LOCAL_NAME = "Advice"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type
    TYPE_LOCAL_NAME = "AdviceType"

    # QName of the XSI type
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    def _getChildren(self, typeOrName=None):
        '''
        Gets the list of all child elements attached to this advice.
        
        @return: the list of all child elements attached to this advice
        '''
        raise NotImplementedError()

    def _getAssertionIDReferences(self):
        '''Gets the list of AssertionID references used as advice.
        
        @return: the list of AssertionID references used as advice
        '''
        raise NotImplementedError()

    def _getAssertionURIReferences(self):
        '''Gets the list of AssertionURI references used as advice.
        
        @return: the list of AssertionURI references used as advice
        '''
        raise NotImplementedError()
    
    def _getAssertions(self):
        '''Gets the list of Assertions used as advice.
        
        @return: the list of Assertions used as advice
        '''
        raise NotImplementedError()
    
    def _getEncryptedAssertions(self):
        '''Gets the list of EncryptedAssertions used as advice.
        
        @return: the list of EncryptedAssertions used as advice
        '''
        raise NotImplementedError()
        

class Assertion(SAMLObject):
    """SAML 2.0 Attribute Assertion for use with NERC DataGrid    
    """    
    ns = "urn:oasis:names:tc:SAML:1.0:assertion"
    nsPfx = "saml"
    issuer = 'http:#badc.nerc.ac.uk'
    attributeName = "urn:mace:dir:attribute-def:eduPersonAffiliation"
    attributeNS = "urn:mace:shibboleth:1.0:attributeNamespace:uri"

    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "Assertion"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "AssertionType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    # Version attribute name.
    VERSION_ATTRIB_NAME = "Version"

    # IssueInstant attribute name.
    ISSUE_INSTANT_ATTRIB_NAME = "IssueInstant"

    # ID attribute name.
    ID_ATTRIB_NAME = "ID"

    __slots__ = (
        '__version',
        '__issueInstant',
        '__id',
        '__issuer',
        '__subject',
        '__conditions',
        '__advice',
        '__statements',
        '__authnStatements',
        '__authzDecisionStatements',
        '__attributeStatements'
    )
    
    def __init__(self):
        # Base class initialisation
        super(Assertion, self).__init__()
        
        self.__version = None
        self.__issueInstant = None
        self.__id = None
        self.__issuer = None
        self.__subject = None
        
        self.__conditions = None
        self.__advice = None
        self.__statements = TypedList(Statement)
        
        # TODO: Implement AuthnStatement and AuthzDecisionStatement classes
        self.__authnStatements = []
        self.__authzDecisionStatements = TypedList(AuthzDecisionStatement)
        self.__attributeStatements = TypedList(AttributeStatement)
        
    def _get_version(self):
        '''@return: the SAML Version of this assertion.
        '''
        return self.__version
    
    def _set_version(self, version):
        '''@param version: the SAML Version of this assertion
        '''
        if not isinstance(version, SAMLVersion):
            raise TypeError("Expecting SAMLVersion type got: %r" % 
                            version.__class__)
        
        self.__version = version
        
    version = property(fget=_get_version,
                       fset=_set_version,
                       doc="SAML Version of the assertion")

    def _get_issueInstant(self):
        '''Gets the issue instance of this assertion.
        
        @return: the issue instance of this assertion'''
        return self.__issueInstant
    
    def _set_issueInstant(self, issueInstant):
        '''Sets the issue instance of this assertion.
        
        @param issueInstant: the issue instance of this assertion
        '''
        if not isinstance(issueInstant, datetime):
            raise TypeError('Expecting "datetime" type for "issueInstant", '
                            'got %r' % issueInstant.__class__)
            
        self.__issueInstant = issueInstant
        
    issueInstant = property(fget=_get_issueInstant, 
                            fset=_set_issueInstant,
                            doc="Issue instant of the assertion")

    def _get_id(self):
        '''Sets the ID of this assertion.
        
        @return: the ID of this assertion
        '''
        return self.__id
    
    def _set_id(self, _id):
        '''Sets the ID of this assertion.
        
        @param _id: the ID of this assertion
        '''
        if not isinstance(_id, basestring):
            raise TypeError('Expecting basestring derived type for "id", got '
                            '%r' % _id.__class__)
        self.__id = _id
        
    id = property(fget=_get_id, fset=_set_id, doc="ID of assertion")
    
    def _set_issuer(self, issuer):
        """Set issuer"""
        if not isinstance(issuer, Issuer):
            raise TypeError("issuer must be %r, got %r" % (Issuer, 
                                                           type(issuer)))
        self.__issuer = issuer
    
    def _get_issuer(self):
        """Get the issuer name """
        return self.__issuer

    issuer = property(fget=_get_issuer, 
                      fset=_set_issuer,
                      doc="Issuer of assertion")
    
    def _set_subject(self, subject):
        """Set subject string."""
        if not isinstance(subject, Subject):
            raise TypeError("subject must be %r, got %r" % (Subject, 
                                                            type(subject)))

        self.__subject = subject
    
    def _get_subject(self):
        """Get subject string."""
        return self.__subject

    subject = property(fget=_get_subject,
                       fset=_set_subject, 
                       doc="Attribute Assertion subject")
    
    def _get_conditions(self):
        """Get conditions string."""
        return self.__conditions
    
    def _set_conditions(self, value):
        """Get conditions string."""
        if not isinstance(value, Conditions):
            raise TypeError("Conditions must be %r, got %r" % (Conditions, 
                                                               type(value)))

        self.__conditions = value

    conditions = property(fget=_get_conditions,
                          fset=_set_conditions,
                          doc="Attribute Assertion conditions")
    
    def _set_advice(self, advice):
        """Set advice string."""
        if not isinstance(advice, basestring):
            raise TypeError("advice must be a string")

        self.__advice = advice
    
    def _get_advice(self):
        """Get advice string."""
        return self.__advice

    advice = property(fget=_get_advice,
                      fset=_set_advice, 
                      doc="Attribute Assertion advice")
    
    @property
    def statements(self):
        """Attribute Assertion statements"""
        return self.__statements
    
    @property
    def authnStatements(self):
        """Attribute Assertion authentication"""
        return self.__authnStatements
    
    @property
    def authzDecisionStatements(self):
        """Attribute Assertion authorisation decision statements"""
        return self.__authzDecisionStatements
    
    @property
    def attributeStatements(self):
        """Attribute Assertion attribute statements"""
        return self.__attributeStatements
    

class AttributeValue(SAMLObject):
    """Base class for Attribute Value type"""
    
    # Element name, no namespace
    DEFAULT_ELEMENT_LOCAL_NAME = "AttributeValue"

    # Default element name
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)
    __slots__ = ()


class XSStringAttributeValue(AttributeValue):
    """XML XS:String Attribute Value type"""
    
    # Local name of the XSI type
    TYPE_LOCAL_NAME = "string"
        
    # QName of the XSI type
    TYPE_NAME = QName(SAMLConstants.XSD_NS, 
                      TYPE_LOCAL_NAME, 
                      SAMLConstants.XSD_PREFIX)
    
    DEFAULT_FORMAT = "%s#%s" % (SAMLConstants.XSD_NS, TYPE_LOCAL_NAME)
  
    __slots__ = ('__value',)
    
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


class StatusDetail(SAMLObject):
    '''Implementation of SAML 2.0 StatusDetail'''
    
    # Local Name of StatusDetail.
    DEFAULT_ELEMENT_LOCAL_NAME = "StatusDetail"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20P_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20P_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "StatusDetailType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20P_PREFIX)
    
    __slots__ = ('__unknownChildren', '__qname')
    
    def __init__(self):
        # child "any" elements.
        self.__unknownChildren = TypedList(SAMLObject)         
        self.__qname = QName(StatusDetail.DEFAULT_ELEMENT_NAME.namespaceURI,
                             StatusDetail.DEFAULT_ELEMENT_NAME,
                             StatusDetail.DEFAULT_ELEMENT_NAME.prefix)
    
    def getUnknownXMLTypes(self, qname=None): 
        if qname is not None:
            if not isinstance(qname, QName):
                raise TypeError("\"qname\" must be a %r derived type, "
                                "got %r" % (QName, type(qname)))
                
            children = []
            for child in self.__unknownChildren:
                childQName = getattr(child, "qname", None)
                if childQName is not None:
                    if childQName.namespaceURI == qname.namespaceURI or \
                       childQName.localPart == qname.localPart:
                        children.append(child)
                        
            return children
        else:
            return self.__unknownChildren
    
    unknownChildren = property(fget=getUnknownXMLTypes,
                               doc="Child objects of Status Detail - may be "
                                   "any type")
                
    def _getQName(self):
        return self.__qname
        
    def _setQName(self, value):
        if not isinstance(value, QName):
            raise TypeError("\"qname\" must be a %r derived type, "
                            "got %r" % (QName, type(value)))
            
        self.__qname = value

    qname = property(fget=_getQName, fset=_setQName, doc="qualified name")
    

class StatusMessage(SAMLObject):
    '''Implementation of SAML 2.0 Status Message'''

    DEFAULT_ELEMENT_LOCAL_NAME = "StatusMessage"
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20P_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20P_PREFIX)
    
    __slots__ = ('__value', '__qname')
    
    def __init__(self):
        # Value attribute URI.
        self.__value = None        
        self.__qname = QName(StatusMessage.DEFAULT_ELEMENT_NAME.namespaceURI,
                             StatusMessage.DEFAULT_ELEMENT_NAME.localPart,
                             StatusMessage.DEFAULT_ELEMENT_NAME.prefix)
              
    def _getValue(self):
        return self.__value
        
    def _setValue(self, value):
        if not isinstance(value, basestring):
            raise TypeError("\"value\" must be a basestring derived type, "
                            "got %r" % type(value))
            
        self.__value = value

    value = property(fget=_getValue, fset=_setValue, 
                     doc="Status message value")
                
    def _getQName(self):
        return self.__qname
        
    def _setQName(self, value):
        if not isinstance(value, QName):
            raise TypeError("\"qname\" must be a %r derived type, "
                            "got %r" % (QName, type(value)))
            
        self.__qname = value

    qname = property(fget=_getQName, fset=_setQName, doc="qualified name")


class StatusCode(SAMLObject):
    '''Implementation of SAML 2.0 StatusCode.'''
    
    # Local Name of StatusCode.
    DEFAULT_ELEMENT_LOCAL_NAME = "StatusCode"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20P_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20P_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "StatusCodeType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20P_PREFIX)

    # Local Name of the Value attribute.
    VALUE_ATTRIB_NAME = "Value"

    # URI for Success status code.
    SUCCESS_URI = "urn:oasis:names:tc:SAML:2.0:status:Success"

    # URI for Requester status code.
    REQUESTER_URI = "urn:oasis:names:tc:SAML:2.0:status:Requester"

    # URI for Responder status code.
    RESPONDER_URI = "urn:oasis:names:tc:SAML:2.0:status:Responder"

    # URI for VersionMismatch status code.
    VERSION_MISMATCH_URI = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"

    # URI for AuthnFailed status code.
    AUTHN_FAILED_URI = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"

    # URI for InvalidAttrNameOrValue status code.
    INVALID_ATTR_NAME_VALUE_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"

    # URI for InvalidNameIDPolicy status code.
    INVALID_NAMEID_POLICY_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"

    # URI for NoAuthnContext status code.
    NO_AUTHN_CONTEXT_URI = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"

    # URI for NoAvailableIDP status code.
    NO_AVAILABLE_IDP_URI = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"

    # URI for NoPassive status code.
    NO_PASSIVE_URI = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"

    # URI for NoSupportedIDP status code.
    NO_SUPPORTED_IDP_URI = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"

    # URI for PartialLogout status code.
    PARTIAL_LOGOUT_URI = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"

    # URI for ProxyCountExceeded status code.
    PROXY_COUNT_EXCEEDED_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"

    # URI for RequestDenied status code.
    REQUEST_DENIED_URI = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"

    # URI for RequestUnsupported status code.
    REQUEST_UNSUPPORTED_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"

    # URI for RequestVersionDeprecated status code.
    REQUEST_VERSION_DEPRECATED_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"

    # URI for RequestVersionTooHigh status code.
    REQUEST_VERSION_TOO_HIGH_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"
    
    # URI for RequestVersionTooLow status code.
    REQUEST_VERSION_TOO_LOW_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"

    # URI for ResourceNotRecognized status code.
    RESOURCE_NOT_RECOGNIZED_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"

    # URI for TooManyResponses status code.
    TOO_MANY_RESPONSES = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"

    # URI for UnknownAttrProfile status code.
    UNKNOWN_ATTR_PROFILE_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"

    # URI for UnknownPrincipal status code.
    UNKNOWN_PRINCIPAL_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"

    # URI for UnsupportedBinding status code.
    UNSUPPORTED_BINDING_URI = \
                "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"

    __slots__ = ('__value', '__childStatusCode', '__qname')
    
    def __init__(self):
        # Value attribute URI.
        self.__value = None
    
        # Nested secondary StatusCode child element.
        self.__childStatusCode = None
        
        self.__qname = QName(StatusCode.DEFAULT_ELEMENT_NAME.namespaceURI,
                             StatusCode.DEFAULT_ELEMENT_NAME.localPart,
                             StatusCode.DEFAULT_ELEMENT_NAME.prefix)

    def _getStatusCode(self): 
        return self.__childStatusCode
    
    def _setStatusCode(self, value):
        if not isinstance(value, StatusCode):
            raise TypeError('Child "statusCode" must be a %r derived type, '
                            "got %r" % (StatusCode, type(value)))
            
        self.__childStatusCode = value

    value = property(fget=_getStatusCode, 
                     fset=_setStatusCode, 
                     doc="Child Status code")
              
    def _getValue(self):
        return self.__value
        
    def _setValue(self, value):
        if not isinstance(value, basestring):
            raise TypeError("\"value\" must be a basestring derived type, "
                            "got %r" % value.__class__)
            
        self.__value = value

    value = property(fget=_getValue, fset=_setValue, doc="Status code value")
                
    def _getQName(self):
        return self.__qname
        
    def _setQName(self, value):
        if not isinstance(value, QName):
            raise TypeError("\"qname\" must be a %r derived type, "
                            "got %r" % (QName, type(value)))
            
        self.__qname = value

    qname = property(fget=_getQName, fset=_setQName, doc="qualified name")
        

class Status(SAMLObject): 
    '''SAML 2.0 Core Status'''
    
    # Local Name of Status.
    DEFAULT_ELEMENT_LOCAL_NAME = "Status"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20P_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20P_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "StatusType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20P_PREFIX)

    __slots__ = ('__statusCode', '__statusMessage', '__statusDetail', '__qname')
    
    def __init__(self):
        # StatusCode element.
        self.__statusCode = None
    
        # StatusMessage element.
        self.__statusMessage = None
    
        # StatusDetail element. 
        self.__statusDetail = None
        
        self.__qname = QName(Status.DEFAULT_ELEMENT_NAME.namespaceURI,
                             Status.DEFAULT_ELEMENT_NAME.localPart,
                             Status.DEFAULT_ELEMENT_NAME.prefix)
                
    def _getQName(self):
        return self.__qname
        
    def _setQName(self, value):
        if not isinstance(value, QName):
            raise TypeError("\"qname\" must be a %r derived type, "
                            "got %r" % (QName, type(value)))
            
        self.__qname = value

    qname = property(fget=_getQName, fset=_setQName, doc="qualified name")
        
    def _getStatusCode(self):
        '''
        Gets the Code of this Status.
        
        @return: Status StatusCode
        '''
        return self.__statusCode

    def _setStatusCode(self, value):
        '''
        Sets the Code of this Status.
        
        @param value:         the Code of this Status
        '''
        if not isinstance(value, StatusCode):
            raise TypeError('"statusCode" must be a %r derived type, '
                            "got %r" % (StatusCode, type(value)))
            
        self.__statusCode = value
        
    statusCode = property(fget=_getStatusCode,
                          fset=_setStatusCode,
                          doc="status code object")
    
    def _getStatusMessage(self):
        '''
        Gets the Message of this Status.
        
        @return: Status StatusMessage
        '''
        return self.__statusMessage

    def _setStatusMessage(self, value):
        '''
        Sets the Message of this Status.
        
        @param value: the Message of this Status
        '''
        if not isinstance(value, StatusMessage):
            raise TypeError('"statusMessage" must be a %r derived type, '
                            "got %r" % (StatusMessage, type(value)))
            
        self.__statusMessage = value
        
    statusMessage = property(fget=_getStatusMessage,
                             fset=_setStatusMessage,
                             doc="status message")

    def _getStatusDetail(self):
        '''
        Gets the Detail of this Status.
        
        @return: Status StatusDetail
        '''
        return self.__statusDetail
    
    def _setStatusDetail(self, value):
        '''
        Sets the Detail of this Status.
        
        @param value: the Detail of this Status
        '''
        self.__statusDetail = value
        
    statusDetail = property(fget=_getStatusDetail,
                            fset=_setStatusDetail,
                            doc="status message")


class Action(SAMLObject): 
    '''SAML 2.0 Core Action'''
    
    # Element local name. 
    DEFAULT_ELEMENT_LOCAL_NAME = "Action"

    # Default element name. 
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)

    # Local name of the XSI type. 
    TYPE_LOCAL_NAME = "ActionType"

    # QName of the XSI type 
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20_PREFIX)

    # Name of the Namespace attribute. 
    NAMESPACE_ATTRIB_NAME = "Namespace"

    # Read/Write/Execute/Delete/Control action namespace. 
    RWEDC_NS_URI = "urn:oasis:names:tc:SAML:1.0:action:rwedc"

    # Read/Write/Execute/Delete/Control negation action namespace. 
    RWEDC_NEGATION_NS_URI = "urn:oasis:names:tc:SAML:1.0:action:rwedc-negation"

    # Get/Head/Put/Post action namespace. 
    GHPP_NS_URI = "urn:oasis:names:tc:SAML:1.0:action:ghpp"

    # UNIX file permission action namespace. 
    UNIX_NS_URI = "urn:oasis:names:tc:SAML:1.0:action:unix"

    ACTION_NS_IDENTIFIERS = (
        RWEDC_NS_URI,
        RWEDC_NEGATION_NS_URI,    
        GHPP_NS_URI,
        UNIX_NS_URI       
    )
    
    # Read action. 
    READ_ACTION = "Read"

    # Write action. 
    WRITE_ACTION = "Write"

    # Execute action. 
    EXECUTE_ACTION = "Execute"

    # Delete action. 
    DELETE_ACTION = "Delete"

    # Control action. 
    CONTROL_ACTION = "Control"

    # Negated Read action. 
    NEG_READ_ACTION = "~Read"

    # Negated Write action. 
    NEG_WRITE_ACTION = "~Write"

    # Negated Execute action. 
    NEG_EXECUTE_ACTION = "~Execute"

    # Negated Delete action. 
    NEG_DELETE_ACTION = "~Delete"

    # Negated Control action. 
    NEG_CONTROL_ACTION = "~Control"

    # HTTP GET action. 
    HTTP_GET_ACTION = "GET"

    # HTTP HEAD action. 
    HTTP_HEAD_ACTION = "HEAD"

    # HTTP PUT action. 
    HTTP_PUT_ACTION = "PUT"

    # HTTP POST action. 
    HTTP_POST_ACTION = "POST"
    
    ACTION_TYPES = {
        RWEDC_NS_URI: (READ_ACTION, WRITE_ACTION, EXECUTE_ACTION, DELETE_ACTION,
                       CONTROL_ACTION),
        RWEDC_NEGATION_NS_URI: (READ_ACTION, WRITE_ACTION, EXECUTE_ACTION, 
                                DELETE_ACTION, CONTROL_ACTION, NEG_READ_ACTION, 
                                NEG_WRITE_ACTION, NEG_EXECUTE_ACTION, 
                                NEG_CONTROL_ACTION),    
        GHPP_NS_URI: (HTTP_GET_ACTION, HTTP_HEAD_ACTION, HTTP_PUT_ACTION,
                      HTTP_POST_ACTION),
                      
        # This namespace uses octal bitmask for file permissions
        UNIX_NS_URI: ()   
    }
    
    def __init__(self, **kw):
        '''Create an authorization action type
        '''
        super(Action, self).__init__(**kw)

        # URI of the Namespace of this action.  Default to read/write/negation 
        # type - 2.7.4.2 SAML 2 Core Spec. 15 March 2005
        self.__namespace = Action.RWEDC_NEGATION_NS_URI

        #Value value
        self.__action = None       
    
        self.__actionTypes = Action.ACTION_TYPES

    def _getActionTypes(self):
        return self.__actionTypes

    def _setActionTypes(self, value):
        if not isinstance(value, dict):
            raise TypeError('Expecting list or tuple type for "actionTypes" '
                            'attribute; got %r' % type(value))
            
        for k, v in value.items():
            if not isinstance(v, (tuple, type(None))):
                raise TypeError('Expecting None or tuple type for '
                                '"actionTypes" dictionary values; got %r for '
                                '%r key' % (type(value), k))
        self.__actionTypes = value

    actionTypes = property(_getActionTypes, 
                           _setActionTypes, 
                           doc="Restrict vocabulary of action types")
        
    def _getNamespace(self):
        '''
        gets the namespace scope of the specified value.
        
        @return: the namespace scope of the specified value
        '''
        return self.__namespace

    def _setNamespace(self, value):
        '''Sets the namespace scope of the specified value.
        
        @param value: the namespace scope of the specified value
        '''
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "namespace" '
                            'attribute; got %r' % type(value))
            
        if value not in self.__actionTypes.keys():
            raise AttributeError('"namespace" action type %r not recognised. '
                                 'It must be one of these action types: %r' % 
                                 self.__actionTypes.keys())
            
        self.__namespace = value

    namespace = property(_getNamespace, _setNamespace, doc="Action Namespace")

    def _getValue(self):
        '''gets the URI of the action to be performed.
        
        @return: the URI of the action to be performed
        '''
        return self.__value

    def _setValue(self, value):
        '''Sets the URI of the action to be performed.
        
        @param value: the URI of the value to be performed
        '''
        # int and oct allow for UNIX file permissions action type
        if not isinstance(value, (basestring, int)):
            raise TypeError('Expecting string or int type for "action" '
                            'attribute; got %r' % type(value))
            
        # Default to read/write/negation type - 2.7.4.2 SAML 2 Core Spec.
        # 15 March 2005
        allowedActions = self.__actionTypes.get(self.__namespace,
                                                Action.RWEDC_NEGATION_NS_URI)
        
        # Only apply restriction for action type that has a restricted 
        # vocabulary - UNIX type is missed out of this because its an octal
        # mask
        if len(allowedActions) > 0 and value not in allowedActions:
            raise AttributeError('%r action not recognised; known actions for '
                                 'the %r namespace identifier are: %r.  ' 
                                 'If this is not as expected make sure to set '
                                 'the "namespace" attribute to an alternative '
                                 'value first or override completely by '
                                 'explicitly setting the "allowTypes" '
                                 'attribute' % 
                                 (value, self.__namespace, allowedActions))
        self.__value = value

    value = property(_getValue, _setValue, doc="Action string")
        

class RequestAbstractType(SAMLObject): 
    '''SAML 2.0 Core RequestAbstractType'''
    
    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "RequestAbstractType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20P_PREFIX)

    # ID attribute name.
    ID_ATTRIB_NAME = "ID"

    # Version attribute name.
    VERSION_ATTRIB_NAME = "Version"

    # IssueInstant attribute name.
    ISSUE_INSTANT_ATTRIB_NAME = "IssueInstant"

    # Destination attribute name.
    DESTINATION_ATTRIB_NAME = "Destination"

    # Consent attribute name.
    CONSENT_ATTRIB_NAME = "Consent"

    # Unspecified consent URI.
    UNSPECIFIED_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:unspecified"

    # Obtained consent URI.
    OBTAINED_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:obtained"

    # Prior consent URI.
    PRIOR_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:prior"

    # Implicit consent URI.
    IMPLICIT_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:implicit"

    # Explicit consent URI.
    EXPLICIT_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:explicit"

    # Unavailable consent URI.
    UNAVAILABLE_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:unavailable"

    # Inapplicable consent URI.
    INAPPLICABLE_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:inapplicable"
     
    __slots__ = (
        '__version',
        '__id',
        '__issueInstant',
        '__destination',
        '__consent',
        '__issuer',
        '__extensions'
    )
    
    def __init__(self):
        # SAML Version of the request. 
        self.__version = None
    
        # Unique identifier of the request. 
        self.__id = None
    
        # Date/time request was issued. 
        self.__issueInstant = None
    
        # URI of the request destination. 
        self.__destination = None
    
        # URI of the SAML user consent type. 
        self.__consent = None
    
        # URI of the SAML user consent type. 
        self.__issuer = None
    
        # Extensions child element. 
        self.__extensions = None
        
    def _get_version(self):
        '''@return: the SAML Version of this assertion.
        '''
        return self.__version
    
    def _set_version(self, version):
        '''@param version: the SAML Version of this assertion
        '''
        if not isinstance(version, SAMLVersion):
            raise TypeError("Expecting SAMLVersion type got: %r" % 
                            version.__class__)
        
        self.__version = version
        
    version = property(fget=_get_version,
                       fset=_set_version,
                       doc="SAML Version of the assertion")

    def _get_issueInstant(self):
        '''Gets the date/time the request was issued
        
        @return: the issue instance of this request'''
        return self.__issueInstant
    
    def _set_issueInstant(self, value):
        '''Sets the date/time the request was issued
        
        @param value: the issue instance of this request
        '''
        if not isinstance(value, datetime):
            raise TypeError('Expecting "datetime" type for "issueInstant", '
                            'got %r' % type(value))
            
        self.__issueInstant = value
        
    issueInstant = property(fget=_get_issueInstant, 
                            fset=_set_issueInstant,
                            doc="Issue instant of the request") 

    def _get_id(self):
        '''Sets the unique identifier for this request.
        
        @return: the ID of this request
        '''
        return self.__id
    
    def _set_id(self, value):
        '''Sets the unique identifier for this request
        
        @param value: the ID of this assertion
        '''
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for "id", got '
                            '%r' % type(value))
        self.__id = value
        
    id = property(fget=_get_id, fset=_set_id, doc="ID of request")

    def _get_destination(self):
        '''Gets the URI of the destination of the request.
        
        @return: the URI of the destination of the request
        '''
        return self.__destination
    
    def _set_destination(self, value):
        '''Sets the URI of the destination of the request.
        
        @param value: the URI of the destination of the request'''
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for '
                            '"destination", got %r' % type(value))
        self.__destination = value
        
    destination = property(fget=_get_destination, 
                           fset=_set_destination,
                           doc="Destination of request")
     
    def _get_consent(self):
        '''Gets the consent obtained from the principal for sending this 
        request.
        
        @return: the consent obtained from the principal for sending this 
        request
        '''
        return self.__consent
        
    def _set_consent(self, value):
        '''Sets the consent obtained from the principal for sending this 
        request.
        
        @param value: the new consent obtained from the principal for 
        sending this request
        ''' 
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for "consent", '
                            'got %r' % type(value))
        self.__consent = value
              
    consent = property(fget=_get_consent, 
                       fset=_set_consent,
                       doc="Consent for request")
   
    def _set_issuer(self, issuer):
        """Set issuer of request"""
        if not isinstance(issuer, Issuer):
            raise TypeError('"issuer" must be a %r, got %r' % (Issuer, 
                                                               type(issuer)))
        
        self.__issuer = issuer
    
    def _get_issuer(self):
        """Get the issuer name """
        return self.__issuer

    issuer = property(fget=_get_issuer, 
                      fset=_set_issuer,
                      doc="Issuer of request")
 
    def _get_extensions(self):
        '''Gets the Extensions of this request.
        
        @return: the Status of this request
        '''
        return self.__extensions
      
    def _set_extensions(self, value):
        '''Sets the Extensions of this request.
        
        @param value: the Extensions of this request
        '''
        self.__extensions = value
        
    extensions = property(fget=_get_extensions, 
                          fset=_set_extensions,
                          doc="Request extensions")


class SubjectQuery(RequestAbstractType):
    """SAML 2.0 Core Subject Query type"""
    __slots__ = ('__subject', )
    
    def __init__(self):
        super(SubjectQuery, self).__init__()
        self.__subject = None
        
    def _getSubject(self):
        '''Gets the Subject of this request.
        
        @return: the Subject of this request'''   
        return self.__subject
    
    def _setSubject(self, value):
        '''Sets the Subject of this request.
        
        @param value: the Subject of this request'''
        if not isinstance(value, Subject):
            raise TypeError('Setting "subject", got %r, expecting %r' %
                            (Subject, type(value)))
            
        self.__subject = value
        
    subject = property(fget=_getSubject, fset=_setSubject, doc="Query subject")
    
    
class AttributeQuery(SubjectQuery):
    '''SAML 2.0 AttributeQuery'''
    
    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "AttributeQuery"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20P_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20P_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "AttributeQueryType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20P_PREFIX)

    __slots__ = ('__attributes',)
    
    def __init__(self):
        super(AttributeQuery, self).__init__()
        self.__attributes = TypedList(Attribute)
 
    def _getAttributes(self):
        '''Gets the Attributes of this query.
        
        @return: the list of Attributes of this query'''
        return self.__attributes

    def _setAttributes(self, value):
        self.__attributes = value

    attributes = property(fget=_getAttributes, 
                          fset=_setAttributes, 
                          doc="Attributes")


class Evidentiary(SAMLObject):
    """Base class for types set in an evidence object"""
    __slots__ = ()


class AssertionURIRef(Evidentiary):
    '''SAML 2.0 Core AssertionURIRef'''
    __slots__ = ('__assertionURI',)
    
    # Element local name
    DEFAULT_ELEMENT_LOCAL_NAME = "AssertionURIRef"

    # Default element name
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)
    
    def __init__(self):
        '''Create assertion URI reference'''
        super(AssertionURIRef, self).__init__()
        
        # URI of the Assertion
        self.__assertionURI = None   

    def _getAssertionURI(self):
        return self.__assertionURI

    def _setAssertionURI(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "assertionID" '
                            'attribute; got %r' % type(value))
        self.__assertionURI = value

    def getOrderedChildren(self):
        return None

    assertionURI = property(_getAssertionURI, _setAssertionURI, 
                            doc="Assertion URI")
    
    
class AssertionIDRef(Evidentiary):
    '''SAML 2.0 Core AssertionIDRef.'''

    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "AssertionIDRef"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX)
    
    __slots__ = ("_AssertionID",)
    
    def __init__(self, namespaceURI, elementLocalName, namespacePrefix):
        '''
        @param namespaceURI: the namespace the element is in
        @param elementLocalName: the local name of the XML element this Object 
        represents
        @param namespacePrefix: the prefix for the given namespace
        '''
        super(AssertionIDRef, self).__init__(namespaceURI, 
                                             elementLocalName, 
                                             namespacePrefix)
        self.__assertionID = None
    
    def _getAssertionID(self):
        '''Gets the ID of the assertion this references.
        
        @return: the ID of the assertion this references'''
        return self.__assertionID
        
    def _setAssertionID(self, value):
        '''Sets the ID of the assertion this references.
        
        @param value: the ID of the assertion this references'''
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "assertionID" '
                            'attribute; got %r' % type(value))
        self.__assertionID = value

    def getOrderedChildren(self):
        return None

    assertionID = property(_getAssertionID, _setAssertionID, 
                           doc="Assertion ID")
        
    
class EncryptedElementType(SAMLObject):
    '''SAML 2.0 Core EncryptedElementType'''
    
    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "EncryptedElementType"
        
    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME, 
                      SAMLConstants.SAML20_PREFIX)
    
    __slots__ = ()
    
    def _getEncryptedData(self):
        '''Get the EncryptedData child element.
        
        @return the EncryptedData child element'''
        raise NotImplementedError()
    
    def _setEncryptedData(self, value):
        '''Set the EncryptedData child element.
        
        @param newEncryptedData the new EncryptedData child element'''
        raise NotImplementedError()
    
    def _getEncryptedKeys(self):
        '''A list of EncryptedKey child elements.
        
        @return a list of EncryptedKey child elements'''
        raise NotImplementedError()
    
    
class EncryptedAssertion(EncryptedElementType, Evidentiary):
    '''SAML 2.0 Core EncryptedAssertion.'''
    
    # Element local name. 
    DEFAULT_ELEMENT_LOCAL_NAME = "EncryptedAssertion"

    # Default element name. 
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20_PREFIX) 
    __slots__ = ()
      
    
class Evidence(SAMLObject):
    '''SAML 2.0 Core Evidence.'''
    
    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "Evidence"
    
    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME, 
                                 SAMLConstants.SAML20_PREFIX)
    
    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "EvidenceType" 
        
    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20_NS, 
                      TYPE_LOCAL_NAME, 
                      SAMLConstants.SAML20_PREFIX)

    __slots__ = ('__values',)
    
    def __init__(self, **kw):
        '''Create an authorization evidence type
        '''
        super(Evidence, self).__init__(**kw)

        # Assertion of the Evidence. 
        self.__values = TypedList(Evidentiary) 
        
    @property
    def assertionIDReferences(self):
        '''Gets the list of AssertionID references used as evidence.
    
        @return: the list of AssertionID references used as evidence'''
        return [i for i in self.__values 
                if (getattr(i, "DEFAULT_ELEMENT_NAME") == 
                    AssertionIDRef.DEFAULT_ELEMENT_NAME)]
    
    @property
    def assertionURIReferences(self):
        '''Gets the list of AssertionURI references used as evidence.
       
        @return: the list of AssertionURI references used as evidence'''
        return [i for i in self.__values 
                if (getattr(i, "DEFAULT_ELEMENT_NAME") == 
                    AssertionURIRef.DEFAULT_ELEMENT_NAME)]
    
    @property
    def assertions(self):
        '''Gets the list of Assertions used as evidence.
       
        @return: the list of Assertions used as evidence'''
        return [i for i in self.__values 
                if (getattr(i, "DEFAULT_ELEMENT_NAME") == 
                    Assertion.DEFAULT_ELEMENT_NAME)]
    
    @property
    def encryptedAssertions(self):
        '''Gets the list of EncryptedAssertions used as evidence.
       
        @return: the list of EncryptedAssertions used as evidence'''
        return [i for i in self.__values 
                if (getattr(i, "DEFAULT_ELEMENT_NAME") == 
                    EncryptedAssertion.DEFAULT_ELEMENT_NAME)]   

    @property
    def values(self):
        '''Gets the list of all elements used as evidence.
       
        @return: the list of Evidentiary objects used as evidence'''
        return self.__values
    
    def getOrderedChildren(self):
        children = []

        if len(self.__values) == 0:
            return None

        children.extend(self.__values)

        return tuple(children)
    

class AuthzDecisionQuery(SubjectQuery):
    '''SAML 2.0 AuthzDecisionQuery.'''

    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "AuthzDecisionQuery"

    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20P_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME,
                                 SAMLConstants.SAML20P_PREFIX)

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "AuthzDecisionQueryType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20P_PREFIX)

    # Resource attribute name.
    RESOURCE_ATTRIB_NAME = "Resource"
    
    __slots__ = (
       '__resource',
       '__evidence',
       '__actions',
       '__normalizeResource',
       '__safeNormalizationChars'
    )
    
    def __init__(self, normalizeResource=True, safeNormalizationChars='/%'):
        '''Create new authorisation decision query
        '''
        super(AuthzDecisionQuery, self).__init__()

        # Resource attribute value. 
        self.__resource = None
    
        # Evidence child element.
        self.__evidence = None
    
        # Action child elements.
        self.__actions = TypedList(Action)   
        
        # Tuning for normalization of resource URIs in property set method
        self.normalizeResource = normalizeResource
        self.safeNormalizationChars = safeNormalizationChars

    def _getNormalizeResource(self):
        return self.__normalizeResource

    def _setNormalizeResource(self, value):
        if not isinstance(value, bool):
            raise TypeError('Expecting bool type for "normalizeResource" '
                            'attribute; got %r instead' % type(value))
            
        self.__normalizeResource = value

    normalizeResource = property(_getNormalizeResource, 
                                 _setNormalizeResource, 
                                 doc="Flag to normalize new resource value "
                                     "assigned to the \"resource\" property.  "
                                     "The setting only applies for URIs "
                                     'beginning with "http://" or "https://"')

    def _getSafeNormalizationChars(self):
        return self.__safeNormalizationChars

    def _setSafeNormalizationChars(self, value):
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "normalizeResource" '
                            'attribute; got %r instead' % type(value))
            
        self.__safeNormalizationChars = value

    safeNormalizationChars = property(_getSafeNormalizationChars, 
                                      _setSafeNormalizationChars, 
                                      doc="String containing a list of "
                                          "characters that should not be "
                                          "converted when Normalizing the "
                                          "resource URI.  These are passed to "
                                          "urllib.quote when the resource "
                                          "property is set.  The default "
                                          "characters are '/%'")

    def _getResource(self):
        '''Gets the Resource attrib value of this query.

        @return: the Resource attrib value of this query'''
        return self.__resource
    
    def _setResource(self, value):
        '''Sets the Resource attrib value of this query normalizing the path
        component, removing spurious port numbers (80 for HTTP and 443 for 
        HTTPS) and converting the host component to lower case.
        
        @param value: the new Resource attrib value of this query'''
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "resource" attribute; '
                            'got %r instead' % type(value))
        
        if (self.normalizeResource and 
            value.startswith('http://') or value.startswith('https://')):
            # Normalise the path, set the host name to lower case and remove 
            # port redundant numbers 80 and 443
            splitResult = urlsplit(value)
            uriComponents = list(splitResult)
            
            # hostname attribute is lowercase
            uriComponents[1] = splitResult.hostname
            
            if splitResult.port is not None:
                isHttpWithStdPort = (splitResult.port == 80 and 
                                     splitResult.scheme == 'http')
                
                isHttpsWithStdPort = (splitResult.port == 443 and
                                      splitResult.scheme == 'https')
                
                if not isHttpWithStdPort and not isHttpsWithStdPort:
                    uriComponents[1] += ":%d" % splitResult.port
            
            uriComponents[2] = urllib.quote(splitResult.path, 
                                            self.safeNormalizationChars)
            
            self.__resource = urlunsplit(uriComponents)
        else:
            self.__resource = value
    
    resource = property(fget=_getResource, fset=_setResource,
                        doc="Resource for which authorisation is requested")
    
    @property
    def actions(self):
        '''The actions for which authorisation is requested
        
        @return: the Actions of this query'''
        return self.__actions
   
    def _getEvidence(self):
        '''Gets the Evidence of this query.

        @return: the Evidence of this query'''
        return self.__evidence

    def _setEvidence(self, value):
        '''Sets the Evidence of this query.
        @param newEvidence: the new Evidence of this query'''  
        if not isinstance(value, Evidence):
            raise TypeError('Expecting Evidence type for "evidence" '
                            'attribute; got %r' % type(value))

        self.__evidence = value  

    evidence = property(fget=_getEvidence, fset=_setEvidence, 
                        doc="A set of assertions which the Authority may use "
                            "to base its authorisation decision on")
    
    def getOrderedChildren(self):
        children = []

        superChildren = super(AuthzDecisionQuery, self).getOrderedChildren()
        if superChildren:
            children.extend(superChildren)

        children.extend(self.__actions)
        
        if self.__evidence is not None:
            children.extend(self.__evidence)

        if len(children) == 0:
            return None

        return tuple(children)


class StatusResponseType(SAMLObject):
    '''SAML 2.0 Core Status Response Type
    '''

    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "StatusResponseType"

    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME,
                      SAMLConstants.SAML20P_PREFIX)

    # ID attribute name
    ID_ATTRIB_NAME = "ID"

    # InResponseTo attribute name
    IN_RESPONSE_TO_ATTRIB_NAME = "InResponseTo"

    # Version attribute name
    VERSION_ATTRIB_NAME = "Version"

    # IssueInstant attribute name
    ISSUE_INSTANT_ATTRIB_NAME = "IssueInstant"

    # Destination attribute name
    DESTINATION_ATTRIB_NAME = "Destination"

    # Consent attribute name.
    CONSENT_ATTRIB_NAME = "Consent"

    # Unspecified consent URI
    UNSPECIFIED_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:unspecified"

    # Obtained consent URI
    OBTAINED_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:obtained"

    # Prior consent URI
    PRIOR_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:prior"

    # Implicit consent URI
    IMPLICIT_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:implicit"

    # Explicit consent URI
    EXPLICIT_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:explicit"

    # Unavailable consent URI
    UNAVAILABLE_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:unavailable"

    # Inapplicable consent URI
    INAPPLICABLE_CONSENT = "urn:oasis:names:tc:SAML:2.0:consent:inapplicable"

    __slots__ = (
        '__qname',        
        '__version',
        '__id',
        '__inResponseTo',
        '__issueInstant',
        '__destination',
        '__consent',
        '__issuer',
        '__status',
        '__extensions'                
    )
    
    def __init__(self):
        self.__qname = None
        
        self.__version = SAMLVersion(SAMLVersion.VERSION_20)
        self.__id = None
        self.__inResponseTo = None
        self.__issueInstant = None
        self.__destination = None
        self.__consent = None
        self.__issuer = None
        self.__status = None
        self.__extensions = None
        
    def _getQName(self):
        return self.__qname
        
    def _setQName(self, value):
        if not isinstance(value, QName):
            raise TypeError("\"qname\" must be a %r derived type, "
                            "got %r" % (QName, type(value)))
            
        self.__qname = value

    qname = property(fget=_getQName, fset=_setQName, doc="qualified name")

    def _get_version(self):
        '''@return: the SAML Version of this response.
        '''
        return self.__version
    
    def _set_version(self, version):
        '''@param version: the SAML Version of this response
        '''
        if not isinstance(version, SAMLVersion):
            raise TypeError("Expecting SAMLVersion type got: %r" % 
                            version.__class__)
        
        self.__version = version
       
    version = property(fget=_get_version,
                       fset=_set_version,
                       doc="SAML Version of the response")

    def _get_id(self):
        '''Sets the ID of this response.
        
        @return: the ID of this response
        '''
        return self.__id
    
    def _set_id(self, value):
        '''Sets the ID of this response.
        
        @param value: the ID of this response
        '''
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for "id", got '
                            '%r' % type(value))
        self.__id = value
        
    id = property(fget=_get_id, fset=_set_id, doc="ID of response")

    def _getInResponseTo(self):
        '''Get the unique request identifier for which this is a response
        
        @return: the unique identifier of the originating 
        request
        '''
        return self.__inResponseTo
    
    def _setInResponseTo(self, value):
        '''Set the unique request identifier for which this is a response
        
        @param value: the unique identifier of the originating 
        request
        '''
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for '
                            '"inResponseTo", got %r' % type(value))
        self.__inResponseTo = value
        
    inResponseTo = property(fget=_getInResponseTo, 
                            fset=_setInResponseTo,
                            doc="unique request identifier for which this is "
                                "a response")

    def _get_issueInstant(self):
        '''Gets the issue instance of this response.
        
        @return: the issue instance of this response'''
        return self.__issueInstant
    
    def _set_issueInstant(self, issueInstant):
        '''Sets the issue instance of this response.
        
        @param newIssueInstance: the issue instance of this response
        '''
        if not isinstance(issueInstant, datetime):
            raise TypeError('Expecting "datetime" type for "issueInstant", '
                            'got %r' % issueInstant.__class__)
            
        self.__issueInstant = issueInstant
        
    issueInstant = property(fget=_get_issueInstant, 
                            fset=_set_issueInstant,
                            doc="Issue instant of the response")

    def _get_destination(self):
        '''Gets the URI of the destination of the response.
        
        @return: the URI of the destination of the response
        '''
        return self.__destination
    
    def _set_destination(self, value):
        '''Sets the URI of the destination of the response.
        
        @param value: the URI of the destination of the response'''
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for '
                            '"destination", got %r' % type(value))
        self.__destination = value
        
    destination = property(fget=_get_destination, 
                           fset=_set_destination,
                           doc="Destination of response")
     
    def _get_consent(self):
        '''Gets the consent obtained from the principal for sending this 
        response.
        
        @return: the consent obtained from the principal for sending this 
        response
        '''
        return self.__consent
        
    def _set_consent(self, value):
        '''Sets the consent obtained from the principal for sending this 
        response.
        
        @param value: the new consent obtained from the principal for 
        sending this response
        ''' 
        if not isinstance(value, basestring):
            raise TypeError('Expecting basestring derived type for "consent", '
                            'got %r' % type(value))
        self.__consent = value
              
    consent = property(fget=_get_consent, 
                       fset=_set_consent,
                       doc="Consent for response")
   
    def _set_issuer(self, issuer):
        """Set issuer of response"""
        if not isinstance(issuer, Issuer):
            raise TypeError('"issuer" must be a %r, got %r' % (Issuer,
                                                               type(issuer)))
        self.__issuer = issuer
    
    def _get_issuer(self):
        """Get the issuer name """
        return self.__issuer

    issuer = property(fget=_get_issuer, 
                      fset=_set_issuer,
                      doc="Issuer of response")
    
    def _getStatus(self):
        '''Gets the Status of this response.
        
        @return: the Status of this response
        '''
        return self.__status

    def _setStatus(self, value):
        '''Sets the Status of this response.
        
        @param newStatus: the Status of this response
        '''
        if not isinstance(value, Status):
            raise TypeError('"status" must be a %r, got %r' % (Status,
                                                               type(value)))
        self.__status = value
        
    status = property(fget=_getStatus, fset=_setStatus, doc="Response status")    
        
    def _get_extensions(self):
        '''Gets the Extensions of this response.
        
        @return: the Status of this response
        '''
        return self.__extensions
      
    def _set_extensions(self, value):
        '''Sets the Extensions of this response.
        
        @param value: the Extensions of this response
        '''
        if not isinstance(value, (list, tuple)):
            raise TypeError('Expecting list or tuple for "extensions", got %r'
                            % type(value))
        self.__extensions = value
        
    extensions = property(fget=_get_extensions, 
                          fset=_set_extensions,
                          doc="Response extensions")    


class Response(StatusResponseType):
    '''SAML2 Core Response'''
    
    # Element local name.
    DEFAULT_ELEMENT_LOCAL_NAME = "Response"
    
    # Default element name.
    DEFAULT_ELEMENT_NAME = QName(SAMLConstants.SAML20P_NS, 
                                 DEFAULT_ELEMENT_LOCAL_NAME, 
                                 SAMLConstants.SAML20P_PREFIX)
    
    # Local name of the XSI type.
    TYPE_LOCAL_NAME = "ResponseType"
        
    # QName of the XSI type.
    TYPE_NAME = QName(SAMLConstants.SAML20P_NS, 
                      TYPE_LOCAL_NAME, 
                      SAMLConstants.SAML20P_PREFIX)
    
    __slots__ = ('__indexedChildren',)
    
    def __init__(self):
        '''''' 
        super(Response, self).__init__()
        
        # Assertion child elements
        self.__indexedChildren = []
    
    def _getAssertions(self): 
        return self.__indexedChildren
    
    assertions = property(fget=_getAssertions,
                          doc="Assertions contained in this response")
