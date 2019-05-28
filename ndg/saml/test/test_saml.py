"""SAML unit test package

NERC DataGrid Project

This implementation is adapted from the Java OpenSAML implementation."""
__author__ = "P J Kershaw"
__date__ = "21/07/09"
__copyright__ = "Copyright 2019 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
    
from datetime import datetime, timedelta
from uuid import uuid4
from io import StringIO

import unittest
import pickle

from ndg.saml import importElementTree
ElementTree = importElementTree()

from ndg.saml.utils import SAMLDateTime
from ndg.saml.saml2.core import (SAMLVersion, Assertion, 
                                 AttributeQuery, Response, Issuer, Subject, 
                                 NameID, StatusCode, StatusMessage, Status, 
                                 Conditions, DecisionType, Action, 
                                 AuthzDecisionQuery)
from ndg.saml.xml.etree import (prettyPrint, AssertionElementTree, 
                                AttributeQueryElementTree, 
                                ResponseElementTree)
from ndg.saml.test.utils import SAMLUtil
            

class SAMLTestCase(unittest.TestCase):
    """Test SAML implementation for use with CMIP5 federation"""
    NAMEID_FORMAT = SAMLUtil.NAMEID_FORMAT
    NAMEID_VALUE = SAMLUtil.NAMEID_VALUE
    ISSUER_DN = SAMLUtil.ISSUER_DN
    UNCORRECTED_RESOURCE_URI = SAMLUtil.UNCORRECTED_RESOURCE_URI
    RESOURCE_URI = SAMLUtil.RESOURCE_URI
    
    def _createAttributeAssertionHelper(self):
        samlUtil = SAMLUtil()
        
        # ESG core attributes
        samlUtil.firstName = "Philip"
        samlUtil.lastName = "Kershaw"
        samlUtil.emailAddress = "p.j.k@somewhere"
        
        # BADC specific attributes
        badcRoleList = (
            'urn:badc:security:authz:1.0:attr:admin', 
            'urn:badc:security:authz:1.0:attr:rapid', 
            'urn:badc:security:authz:1.0:attr:coapec', 
            'urn:badc:security:authz:1.0:attr:midas', 
            'urn:badc:security:authz:1.0:attr:quest', 
            'urn:badc:security:authz:1.0:attr:staff'
        )
        for role in badcRoleList:
            samlUtil.addAttribute("urn:badc:security:authz:1.0:attr", role)
        
        # Make an assertion object
        assertion = samlUtil.buildAssertion()
        
        return assertion
        
    def test01CreateAssertion(self):
         
        assertion = self._createAttributeAssertionHelper()

        
        # Create ElementTree Assertion Element
        assertionElem = AssertionElementTree.toXML(assertion)
        
        self.assertTrue(ElementTree.iselement(assertionElem))
        
        # Serialise to output 
        xmlOutput = prettyPrint(assertionElem)       
        self.assertTrue(len(xmlOutput))
        
        print(("\n"+"_"*80))
        print(xmlOutput)
        print(("_"*80))

    def test02ParseAssertion(self):
        assertion = self._createAttributeAssertionHelper()
        
        # Create ElementTree Assertion Element
        assertionElem = AssertionElementTree.toXML(assertion)
        
        self.assertTrue(ElementTree.iselement(assertionElem))
        
        # Serialise to output 
        xmlOutput = prettyPrint(assertionElem)       
           
        print(("\n"+"_"*80))
        print(xmlOutput)
        print(("_"*80))
                
        assertionStream = StringIO()
        assertionStream.write(xmlOutput)
        assertionStream.seek(0)

        tree = ElementTree.parse(assertionStream)
        elem2 = tree.getroot()
        
        assertion2 = AssertionElementTree.fromXML(elem2)
        self.assertTrue(assertion2)
        
    def test03CreateAttributeQuery(self):
        samlUtil = SAMLUtil()
        samlUtil.firstName = ''
        samlUtil.lastName = ''
        samlUtil.emailAddress = ''
        attributeQuery = samlUtil.buildAttributeQuery(SAMLTestCase.ISSUER_DN,
                                                      SAMLTestCase.NAMEID_VALUE)
        
        elem = AttributeQueryElementTree.toXML(attributeQuery)
        xmlOutput = prettyPrint(elem)
           
        print(("\n"+"_"*80))
        print(xmlOutput)
        print(("_"*80))

    def test04ParseAttributeQuery(self):
        samlUtil = SAMLUtil()
        samlUtil.firstName = ''
        samlUtil.lastName = ''
        samlUtil.emailAddress = ''
        attributeQuery = samlUtil.buildAttributeQuery(SAMLTestCase.ISSUER_DN,
                                                      SAMLTestCase.NAMEID_VALUE)
        
        elem = AttributeQueryElementTree.toXML(attributeQuery)        
        xmlOutput = prettyPrint(elem)       
        print(("\n"+"_"*80))
        print(xmlOutput)
                
        attributeQueryStream = StringIO()
        attributeQueryStream.write(xmlOutput)
        attributeQueryStream.seek(0)

        tree = ElementTree.parse(attributeQueryStream)
        elem2 = tree.getroot()
        
        attributeQuery2 = AttributeQueryElementTree.fromXML(elem2)
        self.assertTrue(attributeQuery2.id == attributeQuery.id)
        self.assertTrue(attributeQuery2.issuer.value==attributeQuery.issuer.value)
        self.assertTrue(attributeQuery2.subject.nameID.value == \
                     attributeQuery.subject.nameID.value)
        
        self.assertTrue(attributeQuery2.attributes[1].name == \
                     attributeQuery.attributes[1].name)
        
        xmlOutput2 = prettyPrint(elem2)       
        print(("_"*80))
        print(xmlOutput2)
        print(("_"*80))

    def _createAttributeQueryResponse(self):
        response = Response()
        response.issueInstant = datetime.utcnow()
        
        # Make up a request ID that this response is responding to
        response.inResponseTo = str(uuid4())
        response.id = str(uuid4())
        response.version = SAMLVersion(SAMLVersion.VERSION_20)
            
        response.issuer = Issuer()
        response.issuer.format = Issuer.X509_SUBJECT
        response.issuer.value = \
                        SAMLTestCase.ISSUER_DN
        
        response.status = Status()
        response.status.statusCode = StatusCode()
        response.status.statusCode.value = StatusCode.SUCCESS_URI
        response.status.statusMessage = StatusMessage()        
        response.status.statusMessage.value = "Response created successfully"
           
        assertion = self._createAttributeAssertionHelper()
        
        # Add a conditions statement for a validity of 8 hours
        assertion.conditions = Conditions()
        assertion.conditions.notBefore = datetime.utcnow()
        assertion.conditions.notOnOrAfter = (assertion.conditions.notBefore + 
                                             timedelta(seconds=60*60*8))
        
        assertion.subject = Subject()  
        assertion.subject.nameID = NameID()
        assertion.subject.nameID.format = SAMLTestCase.NAMEID_FORMAT
        assertion.subject.nameID.value = SAMLTestCase.NAMEID_VALUE    
            
        assertion.issuer = Issuer()
        assertion.issuer.format = Issuer.X509_SUBJECT
        assertion.issuer.value = SAMLTestCase.ISSUER_DN

        response.assertions.append(assertion)
        
        return response
        
    def test05CreateAttributeQueryResponse(self):
        response = self._createAttributeQueryResponse()
        
        # Create ElementTree Assertion Element
        responseElem = ResponseElementTree.toXML(response)
        
        self.assertTrue(ElementTree.iselement(responseElem))
        
        # Serialise to output        
        xmlOutput = prettyPrint(responseElem)       
        self.assertTrue(len(xmlOutput))
        print(("\n"+"_"*80))
        print(xmlOutput)
        print(("_"*80))
    
    def test06CreateAuthzDecisionQuery(self):
        samlUtil = SAMLUtil()
        authzDecisionQuery = samlUtil.buildAuthzDecisionQuery()
        
        self.assertTrue(":80" not in authzDecisionQuery.resource)
        self.assertTrue("localhost" in authzDecisionQuery.resource)
        self.assertTrue(" " not in authzDecisionQuery.resource)
        
        authzDecisionQuery.resource = \
            "https://Somewhere.ac.uk:443/My Secured URI?blah=4&yes=True"
            
        self.assertTrue(":443" not in authzDecisionQuery.resource)
        self.assertTrue("somewhere.ac.uk" in authzDecisionQuery.resource)
        self.assertTrue("yes=True" in authzDecisionQuery.resource)
        
        authzDecisionQuery.actions.append(Action())
        authzDecisionQuery.actions[0].namespace = Action.GHPP_NS_URI
        authzDecisionQuery.actions[0].value = Action.HTTP_GET_ACTION
        
        self.assertTrue(
            authzDecisionQuery.actions[0].value == Action.HTTP_GET_ACTION)
        self.assertTrue(
            authzDecisionQuery.actions[0].namespace == Action.GHPP_NS_URI)
        
        # Try out the restricted vocabulary
        try:
            authzDecisionQuery.actions[0].value = "delete everything"
            self.fail("Expecting AttributeError raised for incorrect action "
                      "setting.")
        except AttributeError as e:
            print(("Caught incorrect action type setting: %s" % e))
        
        authzDecisionQuery.actions[0].actionTypes = {'urn:malicious': 
                                                     ("delete everything",)}
        
        # Try again now that the actipn types have been adjusted
        authzDecisionQuery.actions[0].namespace = 'urn:malicious'
        authzDecisionQuery.actions[0].value = "delete everything"
        
    def test09CreateAuthzDecisionQueryResponse(self):
        response = SAMLUtil.create_authz_decision_query_response()
        self.assertTrue(response.assertions[0])
        self.assertTrue(response.assertions[0].authzDecisionStatements[0])
        self.assertTrue(response.assertions[0].authzDecisionStatements[0
            ].decision == DecisionType.PERMIT)
        self.assertTrue(response.assertions[0].authzDecisionStatements[0
            ].resource == SAMLTestCase.RESOURCE_URI)
        self.assertTrue(response.assertions[0].authzDecisionStatements[0
            ].decision == DecisionType.PERMIT)
        self.assertTrue(response.assertions[0].authzDecisionStatements[0
            ].actions[-1].namespace == Action.GHPP_NS_URI)
        self.assertTrue(response.assertions[0].authzDecisionStatements[0
            ].actions[-1].value == Action.HTTP_GET_ACTION)
 
    def test12PickleAssertion(self):
        # Test pickling with __slots__
        assertion = self._createAttributeAssertionHelper()
        assertion.issuer = Issuer()
        assertion.issuer.format = Issuer.X509_SUBJECT
        assertion.issuer.value = SAMLTestCase.ISSUER_DN
        
        # Use '1' pickle method - default '3' breaks with Pytohn 3 - 
        # elementType instance variable is not defined!
        jar = pickle.dumps(assertion, 1)
        assertion2 = pickle.loads(jar)
        self.assertTrue(isinstance(assertion2, Assertion))
        self.assertTrue(assertion2.issuer.value == assertion.issuer.value)
        self.assertTrue(assertion2.issuer.format == assertion.issuer.format)
        self.assertTrue(len(assertion2.attributeStatements)==1)
        self.assertTrue(len(assertion2.attributeStatements[0].attributes) > 0)
        self.assertTrue(assertion2.attributeStatements[0].attributes[0
                     ].attributeValues[0
                     ].value == assertion.attributeStatements[0].attributes[0
                                ].attributeValues[0].value)
        
    def test13PickleAttributeQuery(self):
        # Test pickling with __slots__
        samlUtil = SAMLUtil()
        samlUtil.firstName = ''
        samlUtil.lastName = ''
        samlUtil.emailAddress = ''
        query = samlUtil.buildAttributeQuery(SAMLTestCase.ISSUER_DN,
                                             SAMLTestCase.NAMEID_VALUE)
        
        jar = pickle.dumps(query)
        query2 = pickle.loads(jar)

        self.assertTrue(isinstance(query2, AttributeQuery))
        self.assertTrue(query2.subject.nameID.value == query.subject.nameID.value)
        self.assertTrue((query2.subject.nameID.format == 
                      query.subject.nameID.format))
        self.assertTrue(query2.issuer.value == query.issuer.value)
        self.assertTrue(query2.issuer.format == query.issuer.format)
        self.assertTrue(query2.issueInstant == query.issueInstant)
        self.assertTrue(query2.id == query.id)
        self.assertTrue(len(query2.attributes) == 3)
        self.assertTrue(query2.attributes[0].name == "urn:esg:first:name")
        self.assertTrue(query2.attributes[1].nameFormat == SAMLUtil.XSSTRING_NS)

    def test14PickleAttributeQueryResponse(self):
        response = self._createAttributeQueryResponse()
        
        jar = pickle.dumps(response)
        response2 = pickle.loads(jar)
        
        self.assertTrue(isinstance(response2, Response))
        self.assertTrue((response2.status.statusCode.value == 
                      response.status.statusCode.value))
        self.assertTrue((response2.status.statusMessage.value == 
                      response.status.statusMessage.value))
        self.assertTrue(len(response2.assertions) == 1)
        self.assertTrue(response2.assertions[0].id == response.assertions[0].id)
        self.assertTrue((response2.assertions[0].conditions.notBefore == 
                      response.assertions[0].conditions.notBefore))
        self.assertTrue((response2.assertions[0].conditions.notOnOrAfter == 
                      response.assertions[0].conditions.notOnOrAfter))
        self.assertTrue(len(response2.assertions[0].attributeStatements) == 1)
        self.assertTrue(len(response2.assertions[0].attributeStatements[0
                                                            ].attributes) == 9)
        self.assertTrue(response2.assertions[0].attributeStatements[0].attributes[1
                     ].attributeValues[0
                     ].value == response.assertions[0].attributeStatements[0
                                    ].attributes[1].attributeValues[0].value)
             
    def test15PickleAuthzDecisionQuery(self):
        samlUtil = SAMLUtil()
        query = samlUtil.buildAuthzDecisionQuery()
             
        jar = pickle.dumps(query)
        query2 = pickle.loads(jar)
        
        self.assertTrue(isinstance(query2, AuthzDecisionQuery))
        self.assertTrue(query.resource == query2.resource)
        self.assertTrue(query.version == query2.version)
        self.assertTrue(len(query2.actions) == 1)
        self.assertTrue(query2.actions[0].value == Action.HTTP_GET_ACTION)
        self.assertTrue(query2.actions[0].namespace == Action.GHPP_NS_URI)

    def test16PickleAuthzDecisionResponse(self):
        response = SAMLUtil.create_authz_decision_query_response()
        
        jar = pickle.dumps(response)
        response2 = pickle.loads(jar)
        
        self.assertTrue(isinstance(response2, Response))
        
        self.assertTrue(len(response.assertions) == 1)
        self.assertTrue(len(response.assertions[0].authzDecisionStatements) == 1)
         
        self.assertTrue(response.assertions[0].authzDecisionStatements[0
                        ].resource == response2.assertions[0
                                        ].authzDecisionStatements[0].resource)
        
        self.assertTrue(len(response.assertions[0].authzDecisionStatements[0
                        ].actions) == 1)
        self.assertTrue(response.assertions[0].authzDecisionStatements[0
                        ].actions[0].value == response2.assertions[0
                                        ].authzDecisionStatements[0
                                                ].actions[0].value)
        
        self.assertTrue(response2.assertions[0].authzDecisionStatements[0
                        ].actions[0].namespace == Action.GHPP_NS_URI)        

        self.assertTrue(response2.assertions[0].authzDecisionStatements[0
                        ].decision == DecisionType.PERMIT)        
        
    def test17SAMLDatetime(self):
        # Test parsing of Datetimes following 
        # http://www.w3.org/TR/xmlschema-2/#dateTime 
        
        # No seconds fraction
        self.assertTrue(SAMLDateTime.fromString('2010-10-20T14:49:50Z'))
        
        self.assertRaises(TypeError, SAMLDateTime.fromString, None)
        
        
if __name__ == "__main__":
    unittest.main()        
