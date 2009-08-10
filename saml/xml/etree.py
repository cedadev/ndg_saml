"""Implementation of SAML 2.0 for NDG Security - ElementTree module for
ElementTree representation of SAML objects

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
import logging
log = logging.getLogger(__name__)

try: # python 2.5
    from xml.etree import cElementTree, ElementTree
except ImportError:
    # if you've installed it yourself it comes this way
    import cElementTree, ElementTree

from ndg.security.common.saml import SAMLObject, Conditions, Assertion, \
    Attribute, AttributeStatement, AttributeValue, XSStringAttributeValue, \
    XSGroupRoleAttributeValue, Response, AttributeQuery, Subject, NameID, \
    Issuer, SAMLVersion, Response, Status, StatusCode
    
from ndg.security.common.saml.xml import XMLObject, IssueInstantXMLObject, \
    XMLObjectParseError, SAMLConstants

from ndg.security.common.utils.etree import QName, getLocalName, prettyPrint

class SAMLElementTree(XMLObject):
    """Implement methods generic to all ElementTree SAML object representations
    """       
#    def parse(self, source):
#        """Read in the XML from source
#        @type source: basestring/file
#        @param source: file path to XML file or file object
#        """
#        tree = ElementTree.parse(source)
#        self.__elem = tree.getroot()
#        
#        return self.__elem
#   
    @staticmethod     
    def serialize(elem):
        """Serialise element tree into string"""
        return cElementTree.tostring(elem)
   
    @staticmethod
    def prettyPrint(elem):
        """Basic pretty printing separating each element on to a new line"""
        return prettyPrint(elem)


class ConditionsElementTree(Conditions, IssueInstantXMLObject):
    """ElementTree based XML representation of Conditions class
    """
    
    @classmethod
    def create(cls, conditions):
        """Make a tree of a XML elements based on the assertion conditions"""
        
        if not isinstance(conditions, Conditions):
            raise TypeError("Expecting %r type got: %r"%(Conditions,condition))
        
        notBeforeStr = cls.datetime2Str(conditions.notBefore)
        notOnOrAfterStr = cls.datetime2Str(conditions.notOnOrAfter)
        attrib = {
            cls.NOT_BEFORE_ATTRIB_NAME: notBeforeStr,
            cls.NOT_ON_OR_AFTER_ATTRIB_NAME: notOnOrAfterStr,
        }
        elem = ElementTree.Element(str(cls.DEFAULT_ELEMENT_NAME), **attrib)
        
        ElementTree._namespace_map[cls.DEFAULT_ELEMENT_NAME.namespaceURI
                                   ] = cls.DEFAULT_ELEMENT_NAME.prefix

        for condition in conditions.conditions:
            raise NotImplementedError("Conditions list creation is not "
                                      "implemented")
                
        return elem
               
class AssertionElementTree(Assertion, IssueInstantXMLObject):
    """ElementTree based XML representation of Assertion class
    """
    
    @classmethod
    def create(cls, 
               assertion, 
               **attributeValueElementTreeFactoryKw):
        """Make a tree of a XML elements based on the assertion"""
        
        if not isinstance(assertion, Assertion):
            raise TypeError("Expecting %r type got: %r"%(Assertion, assertion))
        
        issueInstant = cls.datetime2Str(assertion.issueInstant)
        attrib = {
            cls.ID_ATTRIB_NAME: assertion.id,
            cls.ISSUE_INSTANT_ATTRIB_NAME: issueInstant,
            
            # Nb. Version is a SAMLVersion instance and requires explicit cast
            cls.VERSION_ATTRIB_NAME: str(assertion.version)
        }
        elem = ElementTree.Element(str(cls.DEFAULT_ELEMENT_NAME), **attrib)
        
        ElementTree._namespace_map[cls.DEFAULT_ELEMENT_NAME.namespaceURI
                                   ] = cls.DEFAULT_ELEMENT_NAME.prefix
        
        if assertion.issuer is not None:
            issuerElem = IssuerElementTree.create(assertion.issuer)
            elem.append(issuerElem)
        
        if assertion.subject is not None:
            subjectElem = SubjectElementTree.create(assertion.subject)
            elem.append(subjectElem)

        if assertion.advice:
            raise NotImplementedError("Assertion Advice creation is not "
                                      "implemented")

        if assertion.conditions is not None:
            conditionsElem = ConditionsElementTree.create(assertion.conditions)
            elem.append(conditionsElem)
            
        for statement in assertion.statements:
            raise NotImplementedError("Assertion Statement creation is not "
                                      "implemented")
        
        for authnStatement in assertion.authnStatements:
            raise NotImplementedError("Assertion Authentication Statement "
                                      "creation is not implemented")
        
        for authzDecisionStatement in assertion.authzDecisionStatements:
            raise NotImplementedError("Assertion Authorisation Decision "
                                      "Statement creation is not implemented")
            
        for attributeStatement in assertion.attributeStatements:
            attributeStatementElem = AttributeStatementElementTree.create(
                                        attributeStatement,
                                        **attributeValueElementTreeFactoryKw)
            elem.append(attributeStatementElem)
        
        return elem

  
class AttributeStatementElementTree(SAMLElementTree):
    """ElementTree XML representation of AttributeStatement"""
    
    @classmethod
    def create(cls, 
               attributeStatement, 
               **attributeValueElementTreeFactoryKw):
        if not isinstance(attributeStatement, AttributeStatement):
            raise TypeError("Expecting %r type got: %r" % (AttributeStatement, 
                                                           attributeStatement))
            
        elem = ElementTree.Element(
                                str(AttributeStatement.DEFAULT_ELEMENT_NAME))
        ElementTree._namespace_map[
            AttributeStatement.DEFAULT_ELEMENT_NAME.namespaceURI
        ] = AttributeStatement.DEFAULT_ELEMENT_NAME.prefix 

        for attribute in attributeStatement.attributes:
            # Factory enables support for multiple attribute types
            attributeElem = AttributeElementTree.create(attribute,
                                        **attributeValueElementTreeFactoryKw)
            elem.append(attributeElem)
        
        return elem
    

class AttributeElementTree(SAMLElementTree):
    """ElementTree XML representation of SAML Attribute object.  Extend
    to make Attribute types""" 

    @classmethod
    def create(cls, 
               attribute, 
               **attributeValueElementTreeFactoryKw):
        """Make 'Attribute' element"""
        
        if not isinstance(attribute, Attribute):
            raise TypeError("Expecting %r type got: %r"%(Attribute, attribute))
            
        elem = ElementTree.Element(str(Attribute.DEFAULT_ELEMENT_NAME))
        ElementTree._namespace_map[
            Attribute.DEFAULT_ELEMENT_NAME.namespaceURI
        ] = Attribute.DEFAULT_ELEMENT_NAME.prefix 
        
            
        if attribute.friendlyName:
            elem.set(Attribute.FRIENDLY_NAME_ATTRIB_NAME,
                     attribute.friendlyName) 
             
        if attribute.name:
            elem.set(Attribute.NAME_ATTRIB_NAME, attribute.name)
        
        if attribute.nameFormat:
            elem.set(Attribute.NAME_FORMAT_ATTRIB_NAME, attribute.nameFormat)

        for attributeValue in attribute.attributeValues:
            factory = AttributeValueElementTreeFactory(
                                        **attributeValueElementTreeFactoryKw)
            
            attributeValueElementTree = factory(attributeValue)
            
            attributeValueElem=attributeValueElementTree.create(attributeValue)
            elem.append(attributeValueElem)
            
        return elem
 
    @classmethod
    def parse(cls, elem, **attributeValueElementTreeFactoryKw):
        """Parse ElementTree element into a SAML Attribute object
        
        @type elem: ElementTree.Element
        @param elem: Attribute as ElementTree XML element
        @rtype: ndg.security.common.saml.Attribute
        @return: SAML Attribute
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if getLocalName(elem) != Attribute.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLObjectParseError("No \"%s\" element found" %
                                        Attribute.DEFAULT_ELEMENT_LOCAL_NAME)
            
        attribute = Attribute()
            
        name = elem.attrib.get(Attribute.NAME_ATTRIB_NAME)
        if name is not None:
            attribute.name = name
            
        friendlyName = elem.attrib.get(Attribute.FRIENDLY_NAME_ATTRIB_NAME)
        if friendlyName is not None:
            attribute.friendlyName = friendlyName
            
        nameFormat = elem.attrib.get(Attribute.NAME_FORMAT_ATTRIB_NAME)    
        if nameFormat is not None:
            attribute.nameFormat = nameFormat

        for childElem in elem:
            localName = getLocalName(childElem)
            if localName != AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME:
                raise XMLObjectParseError('Expecting "%s" element; found '
                                    '"%s"' %
                                    (AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME,
                                     localName))
            
            # Find XML type attribute to key which AttributeValue sub type to 
            # instantiate
            attributeValueTypeId = None
            for attribName, attribVal in childElem.attrib.items():
                qname = QName(attribName)
                if qname.localPart == "type":
                    attributeValueTypeId = attribVal
                    break
                
            if attributeValueTypeId is None:
                raise XMLObjectParseError("Unable to determine type for "
                                          "AttributeValue")
                
            factory = AttributeValueElementTreeFactory(
                                        **attributeValueElementTreeFactoryKw)
    
            attributeValueElementTreeClass = factory(attributeValueTypeId)
            attributeValue = attributeValueElementTreeClass.parse(childElem)
            attribute.attributeValues.append(attributeValue)
        
        return attribute
        
    
class AttributeValueElementTreeBase(SAMLElementTree):
    """Base class ElementTree XML representation of SAML Attribute Value""" 
    
    @classmethod
    def create(cls, attributeValue):
        """Make 'Attribute' XML element"""

        if not isinstance(attributeValue, AttributeValue):
            raise TypeError("Expecting %r type got: %r" % (AttributeValue, 
                                                           attributeValue))
            
        elem = ElementTree.Element(str(AttributeValue.DEFAULT_ELEMENT_NAME))
        ElementTree._namespace_map[
            AttributeValue.DEFAULT_ELEMENT_NAME.namespaceURI
        ] = AttributeValue.DEFAULT_ELEMENT_NAME.prefix

        return elem


class XSStringAttributeValueElementTree(AttributeValueElementTreeBase,
                                        XSStringAttributeValue):
    """ElementTree XML representation of SAML String type Attribute Value""" 
    
    @classmethod
    def create(cls, attributeValue):
        """Create an XML representation of the input SAML Attribute Value"""
        elem = AttributeValueElementTreeBase.create(attributeValue)
        
        if not isinstance(attributeValue, XSStringAttributeValue):
            raise TypeError("Expecting %r type got: %r" % 
                            (XSStringAttributeValue, attributeValue)) 
        
        # Have to explicitly add namespace declaration here rather use 
        # ElementTree._namespace_map because the prefixes are used for 
        # attributes not element names        
        elem.set("%s:%s" % (SAMLConstants.XMLNS_PREFIX, 
                            SAMLConstants.XSD_PREFIX),
                 SAMLConstants.XSD_NS)
                                   
        elem.set("%s:%s" % (SAMLConstants.XMLNS_PREFIX, 
                            SAMLConstants.XSI_PREFIX),
                 SAMLConstants.XSI_NS)
        
        elem.set("%s:%s" % (SAMLConstants.XSI_PREFIX, 'type'), 
                 "%s:%s" % (SAMLConstants.XSD_PREFIX, 
                            cls.TYPE_LOCAL_NAME))

        elem.text = attributeValue.value

        return elem

    @classmethod
    def parse(cls, elem):
        """Parse ElementTree xs:string element into a SAML 
        XSStringAttributeValue object
        
        @type elem: ElementTree.Element
        @param elem: Attribute value as ElementTree XML element
        @rtype: ndg.security.common.saml.AttributeValue
        @return: SAML Attribute value
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        localName = getLocalName(elem)
        if localName != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLObjectParseError("No \"%s\" element found" %
                                      cls.DEFAULT_ELEMENT_LOCAL_NAME)
        
        # Parse the attribute type checking that it is set to the expected 
        # string type
        typeQName = QName(SAMLConstants.XSI_NS, tag='type')
        
        typeValue = elem.attrib.get(str(typeQName), '')
        typeValueLocalName = typeValue.split(':')[-1]
        if typeValueLocalName != cls.TYPE_LOCAL_NAME:
            raise XMLObjectParseError('Expecting "%s" type; got "%s"' %
                                      (cls.TYPE_LOCAL_NAME,
                                       typeValueLocalName))
        
        # Update namespace map as an XSI type has been referenced.  This will
        # ensure the correct prefix is applied if it re-serialised.
        ElementTree._namespace_map[SAMLConstants.XSI_NS
                                   ] = SAMLConstants.XSI_PREFIX
                                      
        attributeValue = XSStringAttributeValue()
        if elem.text is not None:
            attributeValue.value = elem.text.strip()

        return attributeValue


class XSGroupRoleAttributeValueElementTree(AttributeValueElementTreeBase,
                                           XSGroupRoleAttributeValue):
    """ElementTree XML representation of Earth System Grid custom Group/Role 
    Attribute Value""" 

    @classmethod
    def create(cls, attributeValue):
        """Create an XML representation of the input SAML Attribute Value"""
        elem = AttributeValueElementTreeBase.create(attributeValue)
        
        if not isinstance(attributeValue, XSGroupRoleAttributeValue):
            raise TypeError("Expecting %r type; got: %r" % 
                            (XSGroupRole, type(attributeValue)))
            
        ElementTree._namespace_map[attributeValue.namespaceURI
                                   ] = attributeValue.namespacePrefix
        
        elem.set(cls.GROUP_ATTRIB_NAME, attributeValue.group)
        elem.set(cls.ROLE_ATTRIB_NAME, attributeValue.role)

        return elem


class AttributeValueElementTreeFactory(object):
    """Class factory for AttributeValue ElementTree classes.  These classes are
    used to represent SAML Attribute value types
    
    @type classMap: dict
    @cvar classMap: mapping between SAML AttributeValue class and its 
    ElementTree handler class
    @type idMap: dict
    @cvar idMap: mapping between SAML AttributeValue string identifier and 
    its ElementTree handler class
    """
    classMap = {
        XSStringAttributeValue: XSStringAttributeValueElementTree
    }
    
    idMap = {
        "xs:string": XSStringAttributeValueElementTree
    }
   
    def __init__(self, customClassMap={}, customIdMap={}): 
        """Set-up a SAML class to ElementTree mapping
        @type customClassMap: dict
        @param customClassMap: mapping for custom SAML AttributeValue classes
        to their respective ElementTree based representations.  This appends
        to self.__classMap
        @type customIdMap: dict
        @param customIdMap: string ID based mapping for custom SAML 
        AttributeValue classes to their respective ElementTree based 
        representations.  As with customClassMap, this appends to
        to the respective self.__idMap
        """
        self.__classMap = AttributeValueElementTreeFactory.classMap
        for samlClass, etreeClass in customClassMap.items(): 
            if not issubclass(samlClass, AttributeValue):
                raise TypeError("Input custom class must be derived from %r, "
                                "got %r instead" % (Attribute, samlClass))
                
            self.__classMap[samlClass] = etreeClass

        self.__idMap = AttributeValueElementTreeFactory.idMap
        for samlId, etreeClass in customIdMap.items(): 
            if not isinstance(samlId, basestring):
                raise TypeError("Input custom SAML identifier must be a "
                                "string, got %r instead" % samlId)
                
            self.__idMap[samlId] = etreeClass
            
    def __call__(self, input):
        """Create an ElementTree object based on the Attribute class type
        passed in
        
        @type input: ndg.security.common.saml.AttributeValue or basestring
        @param input: pass an AttributeValue derived type or a string.  If
        an AttributeValue type, then self.__classMap is checked for a matching
        AttributeValue class entry, if a string is passed, self.__idMap is
        checked for a matching string ID.  In both cases, if a match is 
        found an ElementTree class is returned which can render or parse
        the relevant AttributeValue class
        """
        if isinstance(input, AttributeValue):
            xmlObjectClass = self.__classMap.get(input.__class__)
            if xmlObjectClass is None:
                raise TypeError("no matching XMLObject class representation "
                                "for SAML class %r" % input.__class__)
                
        elif isinstance(input, basestring):
            xmlObjectClass = self.__idMap.get(input)
            if xmlObjectClass is None:
                raise TypeError("no matching XMLObject class representation "
                                "for SAML AttributeValue type %s" % input)
        else:
            raise TypeError("Expecting %r class got %r" % (AttributeValue, 
                                                           type(input)))
            
            
        return xmlObjectClass

        
class IssuerElementTree(SAMLElementTree, Issuer):
    """Represent a SAML Issuer element in XML using ElementTree"""
    
    @classmethod
    def create(cls, issuer):
        """Create an XML representation of the input SAML issuer object"""
        if not isinstance(issuer, Issuer):
            raise TypeError("Expecting %r class got %r" % (Issuer, 
                                                           type(issuer)))
        attrib = {
            cls.FORMAT_ATTRIB_NAME: issuer.format
        }
        elem = ElementTree.Element(str(cls.DEFAULT_ELEMENT_NAME), **attrib)
        ElementTree._namespace_map[issuer.qname.namespaceURI
                                   ] = issuer.qname.prefix
                                   
        elem.text = issuer.value

        return elem

    @classmethod
    def parse(cls, elem):
        """Parse ElementTree element into a SAML Issuer instance"""
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if getLocalName(elem) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLObjectParseError('No "%s" element found' %
                                      cls.DEFAULT_ELEMENT_LOCAL_NAME)
            
        issuerFormat = elem.attrib.get(cls.FORMAT_ATTRIB_NAME)
        if issuerFormat is None:
            raise XMLObjectParseError('No "%s" attribute found in "%s" '
                                        'element' %
                                        (issuerFormat,
                                         cls.DEFAULT_ELEMENT_LOCAL_NAME))
        issuer = Issuer()
        issuer.format = issuerFormat
        issuer.value = elem.text.strip() 
        
        return issuer

        
class NameIdElementTree(SAMLElementTree, NameID):
    """Represent a SAML Name Identifier in XML using ElementTree"""
    
    @classmethod
    def create(cls, nameID):
        """Create an XML representation of the input SAML Name Identifier
        object
        @type nameID: ndg.security.common.saml.Subject
        @param nameID: SAML subject
        @rtype: ElementTree.Element
        @return: Name ID as ElementTree XML element"""
        
        if not isinstance(nameID, NameID):
            raise TypeError("Expecting %r class got %r" % (NameID, 
                                                           type(nameID)))
        attrib = {
            cls.FORMAT_ATTRIB_NAME: nameID.format
        }
        elem = ElementTree.Element(str(cls.DEFAULT_ELEMENT_NAME), **attrib)
        
        ElementTree._namespace_map[nameID.qname.namespaceURI
                                   ] = nameID.qname.prefix
        
        elem.text = nameID.value

        return elem

    @classmethod
    def parse(cls, elem):
        """Parse ElementTree element into a SAML NameID object
        
        @type elem: ElementTree.Element
        @param elem: Name ID as ElementTree XML element
        @rtype: ndg.security.common.saml.NameID
        @return: SAML Name ID
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if getLocalName(elem) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLObjectParseError("No \"%s\" element found" %
                                      cls.DEFAULT_ELEMENT_LOCAL_NAME)
            
        format = elem.attrib.get(NameID.FORMAT_ATTRIB_NAME)
        if format is None:
            raise XMLObjectParseError('No "%s" attribute found in "%s" '
                                      'element' %
                                      (format,
                                       cls.DEFAULT_ELEMENT_LOCAL_NAME))
        nameID = NameID()
        nameID.format = format
        nameID.value = elem.text.strip() 
        
        return nameID


class SubjectElementTree(SAMLElementTree, Subject):
    """Represent a SAML Subject in XML using ElementTree"""
    
    @classmethod
    def create(cls, subject):
        """Create an XML representation of the input SAML subject object
        @type subject: ndg.security.common.saml.Subject
        @param subject: SAML subject
        @rtype: ElementTree.Element
        @return: subject as ElementTree XML element
        """
        if not isinstance(subject, Subject):
            raise TypeError("Expecting %r class got %r" % (Subject, 
                                                           type(subject)))
            
        elem = ElementTree.Element(str(Subject.DEFAULT_ELEMENT_NAME))
        
        ElementTree._namespace_map[cls.DEFAULT_ELEMENT_NAME.namespaceURI
                                   ] = cls.DEFAULT_ELEMENT_NAME.prefix

            
        nameIdElem = NameIdElementTree.create(subject.nameID)
        elem.append(nameIdElem)
        
        return elem

    @classmethod
    def parse(cls, elem):
        """Parse ElementTree element into a SAML Subject object
        
        @type elem: ElementTree.Element
        @param elem: subject as ElementTree XML element
        @rtype: ndg.security.common.saml.Subject
        @return: SAML subject
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if getLocalName(elem) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLObjectParseError("No \"%s\" element found" %
                                      cls.DEFAULT_ELEMENT_LOCAL_NAME)
            
        if len(elem) != 1:
            raise XMLObjectParseError("Expecting single Name ID child element "
                                      "for SAML Subject element")
            
        subject = Subject()
        subject.nameID = NameIdElementTree.parse(elem[0])
        
        return subject

        
class StatusCodeElementTree(StatusCode):
    """Represent a SAML Name Identifier in XML using ElementTree"""
    
    @classmethod
    def create(cls, statusCode):
        """Create an XML representation of the input SAML Name Status Code
        
        @type statusCode: ndg.security.common.saml.StatusCode
        @param statusCode: SAML Status Code
        @rtype: ElementTree.Element
        @return: Status Code as ElementTree XML element"""
        
        if not isinstance(statusCode, StatusCode):
            raise TypeError("Expecting %r class got %r" % (StatusCode, 
                                                           type(statusCode)))

        elem = ElementTree.Element(str(cls.DEFAULT_ELEMENT_NAME))
        
        ElementTree._namespace_map[statusCode.qname.namespaceURI
                                   ] = statusCode.qname.prefix
        
        elem.text = statusCode.value

        return elem

    @classmethod
    def parse(cls, elem):
        """Parse ElementTree element into a SAML StatusCode object
        
        @type elem: ElementTree.Element
        @param elem: Status Code as ElementTree XML element
        @rtype: ndg.security.common.saml.StatusCode
        @return: SAML Status Code
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if getLocalName(elem) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLObjectParseError('No "%s" element found' %
                                      cls.DEFAULT_ELEMENT_LOCAL_NAME)
            
        statusCode = StatusCode()
        statusCode.format = format
        statusCode.value = elem.text.strip() 
        
        return statusCode


class StatusElementTree(Status):
    """Represent a SAML Status in XML using ElementTree"""
    
    @classmethod
    def create(cls, status):
        """Create an XML representation of the input SAML subject object
        @type subject: ndg.security.common.saml.Status
        @param subject: SAML subject
        @rtype: ElementTree.Element
        @return: subject as ElementTree XML element
        """
        if not isinstance(status, Status):
            raise TypeError("Expecting %r class got %r" % (status, 
                                                           type(Status)))
            
        elem = ElementTree.Element(str(Status.DEFAULT_ELEMENT_NAME))
        
        ElementTree._namespace_map[cls.DEFAULT_ELEMENT_NAME.namespaceURI
                                   ] = cls.DEFAULT_ELEMENT_NAME.prefix
        
        statusCodeElem = StatusCodeElementTree.create(status.statusCode)
        elem.append(statusCodeElem)
        
        return elem

    @classmethod
    def parse(cls, elem):
        """Parse ElementTree element into a SAML Status object
        
        @type elem: ElementTree.Element
        @param elem: subject as ElementTree XML element
        @rtype: ndg.security.common.saml.Status
        @return: SAML subject
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if getLocalName(elem) != Status.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLObjectParseError('No "%s" element found' %
                                      Status.DEFAULT_ELEMENT_LOCAL_NAME)
            
        if len(elem) != 1:
            raise XMLObjectParseError("Expecting single StatusCode child "
                                      "element for SAML Status element")
            
        status = Status()
        status.statusCode = StatusCodeElementTree.parse(elem[0])
        
        return status
    
    
class AttributeQueryElementTree(AttributeQuery, IssueInstantXMLObject):
    """Represent a SAML Attribute Query in XML using ElementTree"""
        
    @classmethod
    def create(cls, 
               attributeQuery, 
               **attributeValueElementTreeFactoryKw):
        """Create an XML representation of the input SAML Attribute Query
        object

        @type attributeQuery: ndg.security.common.saml.AttributeQuery
        @param attributeQuery: SAML Attribute Query
        @rtype: ElementTree.Element
        @return: Attribute Query as ElementTree XML element
        """
        if not isinstance(attributeQuery, AttributeQuery):
            raise TypeError("Expecting %r class got %r" % (AttributeQuery, 
                                                        type(attributeQuery)))
            
        
        issueInstant = cls.datetime2Str(attributeQuery.issueInstant)
        attrib = {
            cls.ID_ATTRIB_NAME: attributeQuery.id,
            cls.ISSUE_INSTANT_ATTRIB_NAME: issueInstant,
            
            # Nb. Version is a SAMLVersion instance and requires explicit cast
            cls.VERSION_ATTRIB_NAME: str(attributeQuery.version)
        }
                 
        elem = ElementTree.Element(str(cls.DEFAULT_ELEMENT_NAME), **attrib)
        
        ElementTree._namespace_map[cls.DEFAULT_ELEMENT_NAME.namespaceURI
                                   ] = cls.DEFAULT_ELEMENT_NAME.prefix
        
        issuerElem = IssuerElementTree.create(attributeQuery.issuer)
        elem.append(issuerElem)

        subjectElem = SubjectElementTree.create(attributeQuery.subject)
        elem.append(subjectElem)

        for attribute in attributeQuery.attributes:
            # Factory enables support for multiple attribute types
            attributeElem = AttributeElementTree.create(attribute,
                                        **attributeValueElementTreeFactoryKw)
            elem.append(attributeElem)
        
        return elem

    @classmethod
    def parse(cls, elem):
        """Parse ElementTree element into a SAML AttributeQuery object
        
        @type elem: ElementTree.Element
        @param elem: XML element containing the AttributeQuery
        @rtype: ndg.security.common.saml.AttributeQuery
        @return: AttributeQuery object
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if getLocalName(elem) != cls.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLObjectParseError("No \"%s\" element found" %
                                    cls.DEFAULT_ELEMENT_LOCAL_NAME)
        
        # Unpack attributes from top-level element
        attributeValues = []
        for attributeName in (cls.VERSION_ATTRIB_NAME,
                              cls.ISSUE_INSTANT_ATTRIB_NAME,
                              cls.ID_ATTRIB_NAME):
            attributeValue = elem.attrib.get(attributeName)
            if attributeValue is None:
                raise XMLObjectParseError('No "%s" attribute found in "%s" '
                                 'element' %
                                 (attributeName,
                                  cls.DEFAULT_ELEMENT_LOCAL_NAME))
                
            attributeValues.append(attributeValue)
        
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(attributeValues[0])
        if attributeQuery.version != SAMLVersion.VERSION_20:
            raise NotImplementedError("Parsing for %r is implemented for "
                                      "SAML version %s only; version %s is " 
                                      "not supported" % 
                                      (cls,
                                       SAMLVersion(SAMLVersion.VERSION_20),
                                       SAMLVersion(attributeQuery.version)))
            
        attributeQuery.issueInstant = cls.str2Datetime(attributeValues[1])
        attributeQuery.id = attributeValues[2]
        
        for childElem in elem:
            localName = getLocalName(childElem)
            if localName == Issuer.DEFAULT_ELEMENT_LOCAL_NAME:
                # Parse Issuer
                attributeQuery.issuer = IssuerElementTree.parse(childElem)
                
            elif localName == Subject.DEFAULT_ELEMENT_LOCAL_NAME:
                # Parse Subject
                attributeQuery.subject = SubjectElementTree.parse(childElem)
            
            elif localName == Attribute.DEFAULT_ELEMENT_LOCAL_NAME:
                attribute = AttributeElementTree.parse(childElem)
                attributeQuery.attributes.append(attribute)
            else:
                raise XMLObjectParseError("Unrecognised AttributeQuery child "
                                          "element \"%s\"" % localName)
        
        return attributeQuery
        
    
class ResponseElementTree(Response, IssueInstantXMLObject):
    """Represent a SAML Response in XML using ElementTree"""
        
    @classmethod
    def create(cls, 
               response, 
               **attributeValueElementTreeFactoryKw):
        """Create an XML representation of the input SAML Response
        object

        @type response: ndg.security.common.saml.Response
        @param response: SAML Response
        @rtype: ElementTree.Element
        @return: Response as ElementTree XML element
        """
        if not isinstance(response, Response):
            raise TypeError("Expecting %r class, got %r" % (Response, 
                                                            type(response)))
            
        
        issueInstant = cls.datetime2Str(response.issueInstant)
        attrib = {
            cls.ID_ATTRIB_NAME: response.id,
            cls.ISSUE_INSTANT_ATTRIB_NAME: issueInstant,
            cls.IN_RESPONSE_TO_ATTRIB_NAME: response.inResponseTo,
            
            # Nb. Version is a SAMLVersion instance and requires explicit cast
            cls.VERSION_ATTRIB_NAME: str(response.version)
        }
                 
        elem = ElementTree.Element(str(cls.DEFAULT_ELEMENT_NAME), **attrib)
        
        ElementTree._namespace_map[cls.DEFAULT_ELEMENT_NAME.namespaceURI
                                   ] = cls.DEFAULT_ELEMENT_NAME.prefix
            
        issuerElem = IssuerElementTree.create(response.issuer)
        elem.append(issuerElem)

        statusElem = StatusElementTree.create(response.status)       
        elem.append(statusElem)

        for assertion in response.assertions:
            # Factory enables support for multiple attribute types
            assertionElem = AssertionElementTree.create(assertion,
                                        **attributeValueElementTreeFactoryKw)
            elem.append(assertionElem)
        
        return elem

    @classmethod
    def parse(cls, elem):
        """Parse ElementTree element into a SAML Response object
        
        @type elem: ElementTree.Element
        @param elem: XML element containing the Response
        @rtype: ndg.security.common.saml.Response
        @return: Response object
        """
        if not ElementTree.iselement(elem):
            raise TypeError("Expecting %r input type for parsing; got %r" %
                            (ElementTree.Element, elem))

        if getLocalName(elem) != Response.DEFAULT_ELEMENT_LOCAL_NAME:
            raise XMLObjectParseError("No \"%s\" element found" %
                                    Response.DEFAULT_ELEMENT_LOCAL_NAME)
        
        # Unpack attributes from top-level element
        attributeValues = []
        for attributeName in (Response.VERSION_ATTRIB_NAME,
                              Response.ISSUE_INSTANT_ATTRIB_NAME,
                              Response.ID_ATTRIB_NAME,
                              Response.IN_RESPONSE_TO_ATTRIB_NAME):
            attributeValue = elem.attrib.get(attributeName)
            if attributeValue is None:
                raise XMLObjectParseError('No "%s" attribute found in "%s" '
                                          'element' %
                                         (attributeName,
                                          Response.DEFAULT_ELEMENT_LOCAL_NAME))
                
            attributeValues.append(attributeValue)
        
        response = Response()
        response.version = SAMLVersion(attributeValues[0])
        if response.version != SAMLVersion.VERSION_20:
            raise NotImplementedError("Parsing for %r is implemented for "
                                      "SAML version %s only; version %s is " 
                                      "not supported" % 
                                      (cls,
                                       SAMLVersion(SAMLVersion.VERSION_20),
                                       SAMLVersion(response.version)))
            
        response.issueInstant = cls.str2Datetime(attributeValues[1])
        response.id = attributeValues[2]
        response.inResponseTo = attributeValues[3]
        
        for childElem in elem:
            localName = getLocalName(childElem)
            if localName == Issuer.DEFAULT_ELEMENT_LOCAL_NAME:
                # Parse Issuer
                response.issuer = IssuerElementTree.parse(childElem)
            
            elif localName == Status.DEFAULT_ELEMENT_LOCAL_NAME:
                # Get status of response
                response.status = StatusElementTree.parse(childElem)
                
            elif localName == Subject.DEFAULT_ELEMENT_LOCAL_NAME:
                # Parse Subject
                response.subject = SubjectElementTree.parse(childElem)
            
            elif localName == Assertion.DEFAULT_ELEMENT_LOCAL_NAME:
                response.assertions.append(
                                        AssertionElementTree.parse(childElem))
            else:
                raise XMLObjectParseError('Unrecognised Response child '
                                          'element "%s"' % localName)
        
        return response

