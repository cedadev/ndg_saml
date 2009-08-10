"""Attribute Authority SAML Interface unit test package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "21/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
import unittest

from datetime import datetime
import base64 
import os
from uuid import uuid4
import paste.fixture
from cStringIO import StringIO

from ndg.security.common.saml import Assertion, Attribute, AttributeValue, \
    AttributeStatement, SAMLVersion, Subject, NameID, Issuer, AttributeQuery, \
    XSStringAttributeValue
from ndg.security.common.saml.xml import XMLConstants
from ndg.security.common.saml.xml.etree import AssertionElementTree, \
    AttributeQueryElementTree, ResponseElementTree
    
from ndg.security.common.soap.etree import SOAPEnvelope


class SamlSoapBindingApp(object):
    def __init__(self):
        self.firstName = "Philip"
        self.lastName = "Kershaw"
        self.emailAddress = "pkershaw@somewhere.ac.uk"
                  
    def __call__(self, environ, start_response):
        soapRequestStream = environ['wsgi.input']
        soapRequest = SOAPEnvelope()
        soapRequest.parse(soapRequestStream)
        attributeQueryElem = soapRequest.body.elem[0]
        attributeQuery = AttributeQueryElementTree.parse(attributeQueryElem)
        
        print("Received request from client:\n")
        print soapRequest.prettyPrint()
        
        assertion = Assertion()
        assertion.version = SAMLVersion(SAMLVersion.VERSION_20)
        assertion.id = str(uuid4())
        assertion.issueInstant = datetime.utcnow()
        assertion.attributeStatements.append(AttributeStatement())
        attributes = []
        
        for attribute in attributeQuery.attributes:
            if attribute.name == "urn:esg:first:name":
                # special case handling for 'FirstName' attribute
                fnAttribute = Attribute()
                fnAttribute.name = attribute.name
                fnAttribute.nameFormat = attribute.nameFormat
                fnAttribute.friendlyName = attribute.friendlyName
    
                firstName = XSStringAttributeValue()
                firstName.value = self.firstName
                fnAttribute.attributeValues.append(firstName)
    
                attributes.append(fnAttribute)
            
            elif attribute.name == "urn:esg:last:name":
                lnAttribute = Attribute()
                lnAttribute.name = attribute.name
                lnAttribute.nameFormat = attribute.nameFormat
                lnAttribute.friendlyName = attribute.friendlyName
    
                lastName = XSStringAttributeValue()
                lastName.value = self.lastName
                lnAttribute.attributeValues.append(lastName)
    
                attributes.append(lnAttribute)
               
            elif attribute.name == "urn:esg:email:address":
                emailAddressAttribute = Attribute()
                emailAddressAttribute.name = attribute.name
                emailAddressAttribute.nameFormat = attribute.nameFormat
                emailAddressAttribute.friendlyName = attribute.friendlyName
    
                emailAddress = XSStringAttributeValue()
                emailAddress.value = self.emailAddress
                emailAddressAttribute.attributeValues.append(emailAddress)
    
                attributes.append(emailAddressAttribute)
                
            assertion.attributeStatements[0].attributes = attributes
            
        soapResponse = SOAPEnvelope()
        soapResponse.create()
        response = soapResponse.serialize()
        start_response("200 OK",
                       [('Content-length', str(len(response))),
                        ('Content-type', 'text/xml')])
        return [response]

        
class SamlAttributeAuthorityInterfaceTestCase(unittest.TestCase):
    """TODO: test SAML Attribute Authority interface"""
    thisDir = os.path.dirname(os.path.abspath(__file__))

    def __init__(self, *args, **kwargs):
        wsgiApp = SamlSoapBindingApp()
        self.app = paste.fixture.TestApp(wsgiApp)
         
        unittest.TestCase.__init__(self, *args, **kwargs)
        

    def test01AttributeQuery(self):
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = \
                        "/O=NDG/OU=BADC/CN=attributeauthority.badc.rl.ac.uk"
                        
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = "urn:esg:openid"
        attributeQuery.subject.nameID.value = \
                                    "https://openid.localhost/philip.kershaw"
        
        # special case handling for 'FirstName' attribute
        fnAttribute = Attribute()
        fnAttribute.name = "urn:esg:first:name"
        fnAttribute.nameFormat = "http://www.w3.org/2001/XMLSchema#string"
        fnAttribute.friendlyName = "FirstName"

        attributeQuery.attributes.append(fnAttribute)
    
        # special case handling for 'LastName' attribute
        lnAttribute = Attribute()
        lnAttribute.name = "urn:esg:last:name"
        lnAttribute.nameFormat = "http://www.w3.org/2001/XMLSchema#string"
        lnAttribute.friendlyName = "LastName"

        attributeQuery.attributes.append(lnAttribute)
    
        # special case handling for 'LastName' attribute
        emailAddressAttribute = Attribute()
        emailAddressAttribute.name = "urn:esg:email:address"
        emailAddressAttribute.nameFormat = XMLConstants.XSD_NS+"#"+\
                                    XSStringAttributeValue.TYPE_LOCAL_NAME
        emailAddressAttribute.friendlyName = "emailAddress"

        attributeQuery.attributes.append(emailAddressAttribute)                                   
        
        elem = AttributeQueryElementTree.create(attributeQuery)
        query = AttributeQueryElementTree.serialize(elem)
        soapRequest = SOAPEnvelope()
        soapRequest.create()
        soapRequest.body.elem.append(elem)
        
        request = soapRequest.serialize()
        
        header = {
            'soapAction': "http://www.oasis-open.org/committees/security",
            'Content-length': str(len(request)),
            'Content-type': 'text/xml'
        }
        response = self.app.post('/attributeauthority', 
                                 params=request, 
                                 headers=header, 
                                 status=200)
        print("Response status=%d" % response.status)

        soapResponse = SOAPEnvelope()
        
        responseStream = StringIO()
        responseStream.write(response.body)
        responseStream.seek(0)
        
        soapResponse.parse(responseStream)
        
        print("Parsed response ...")
        print(soapResponse.serialize())
      
    def test02AttributeQueryWithSOAPClient(self):
        from ndg.security.common.soap.client import UrlLib2SOAPClient, \
            UrlLib2SOAPRequest
            
        client = UrlLib2SOAPClient()
        
        # ElementTree based envelope class
        client.responseEnvelopeClass = SOAPEnvelope
        
        request = UrlLib2SOAPRequest()
        request.url = \
        'https://esg.prototype.ucar.edu/saml/soap/secure/attributeService.htm'
        request.envelope = SOAPEnvelope()
        request.envelope.create()
        
        # Make an attribute query
        attributeQuery = AttributeQuery()
        attributeQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
        attributeQuery.id = str(uuid4())
        attributeQuery.issueInstant = datetime.utcnow()
        
        attributeQuery.issuer = Issuer()
        attributeQuery.issuer.format = Issuer.X509_SUBJECT
        attributeQuery.issuer.value = \
                        "/O=NDG/OU=BADC/CN=attributeauthority.badc.rl.ac.uk"
                        
                        
        attributeQuery.subject = Subject()  
        attributeQuery.subject.nameID = NameID()
        attributeQuery.subject.nameID.format = "urn:esg:openid"
        attributeQuery.subject.nameID.value = \
                            "https://esg.prototype.ucar.edu/myopenid/testUser"
        
        # special case handling for 'FirstName' attribute
        fnAttribute = Attribute()
        fnAttribute.name = "urn:esg:first:name"
        fnAttribute.nameFormat = "http://www.w3.org/2001/XMLSchema#string"
        fnAttribute.friendlyName = "FirstName"

        attributeQuery.attributes.append(fnAttribute)
    
        # special case handling for 'LastName' attribute
        lnAttribute = Attribute()
        lnAttribute.name = "urn:esg:last:name"
        lnAttribute.nameFormat = "http://www.w3.org/2001/XMLSchema#string"
        lnAttribute.friendlyName = "LastName"

        attributeQuery.attributes.append(lnAttribute)
    
        # special case handling for 'LastName' attribute
        emailAddressAttribute = Attribute()
        emailAddressAttribute.name = "urn:esg:email:address"
        emailAddressAttribute.nameFormat = XMLConstants.XSD_NS+"#"+\
                                    XSStringAttributeValue.TYPE_LOCAL_NAME
        emailAddressAttribute.friendlyName = "emailAddress"

        attributeQuery.attributes.append(emailAddressAttribute)                                   
        
        attributeQueryElem = AttributeQueryElementTree.create(attributeQuery)

        # Attach query to SOAP body
        request.envelope.body.elem.append(attributeQueryElem)
        
        from M2Crypto.m2urllib2 import HTTPSHandler
        from urllib2 import URLError

        client.openerDirector.add_handler(HTTPSHandler())
        try:
            response = client.send(request)
        except URLError, e:
            self.fail("Error calling Attribute Service")
        
        print("Response from server:\n\n%s" % response.envelope.serialize())
        
        if len(response.envelope.body.elem) != 1:
            self.fail("Expecting single child element is SOAP body")
            
        if getLocalName(response.envelope.body.elem[0]) != 'Response':
            self.fail('Expecting "Response" element in SOAP body')
            
        response = ResponseElementTree.parse(response.envelope.body.elem[0])
            
if __name__ == "__main__":
    unittest.main()        

