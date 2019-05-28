"""Test serialisation and deserialisation of SAML XML

Implementation of SAML 2.0 for NDG Security

NERC DataGrid Project

This implementation is adapted from the Java OpenSAML implementation."""
__author__ = "P J Kershaw"
__date__ = "25/01/16"
__copyright__ = "Copyright 2019 United Kingdom Research and Innovation"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level package directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
import unittest
from io import StringIO

from ndg.saml import importElementTree
ElementTree = importElementTree()

from ndg.saml.saml2.core import Response, Action, DecisionType
from ndg.saml.xml.etree import (ResponseElementTree, 
                                AuthzDecisionQueryElementTree, prettyPrint)
from ndg.saml.test.utils import SAMLUtil


class SamlXmlTestCase(unittest.TestCase):

    def test01_missing_action_namespace(self):
        # Handle case where response has used an invalid namespace URI for the
        # action specified.  In the example below 'GET' is used which belongs
        # to the urn:oasis:names:tc:SAML:1.0:action:ghpp namespace.  However,
        # it has not been set so the parser should interpret it as the default
        # urn:oasis:names:tc:SAML:1.0:action:rwedc-negation -
        # 2.7.4.2 SAML 2 Core Spec. 15 March 2005
        saml_resp = '''
<samlp:Response ID="1a0c8a92-f408-4ab6-b352-dc9ae5f025cb" 
InResponseTo="d78f66ec-ddce-4a2a-81cf-6bb2bf5ea624" 
IssueInstant="2016-01-24T06:06:04.389161Z" Version="2.0" 
xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
<saml:Issuer 
Format="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName" 
xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">/C=GB/O=NDG/CN=localhost
</saml:Issuer>
<samlp:Status>
<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
</samlp:Status>
<saml:Assertion ID="41aaf9d3-b637-4d54-ac7f-0b35316c4558" 
IssueInstant="2016-01-24T06:06:04.586012Z" Version="2.0" 
xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
<saml:Issuer 
Format="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName">
/C=GB/O=NDG/CN=localhost
</saml:Issuer>
<saml:Subject>
<saml:NameID Format="urn:esg:openid" /></saml:Subject>
<saml:Conditions NotBefore="2016-01-24T06:06:04.586012Z" 
NotOnOrAfter="2016-01-25T06:06:04.586012Z" />
<saml:AuthzDecisionStatement Decision="Deny" 
Resource="http://localhost:8000/resource.html" >
<saml:Action>GET</saml:Action>
</saml:AuthzDecisionStatement>
</saml:Assertion></samlp:Response>
'''
        authz_decision_response_stream = StringIO()
        authz_decision_response_stream.write(saml_resp)
        authz_decision_response_stream.seek(0)

        tree = ElementTree.parse(authz_decision_response_stream)
        elem = tree.getroot()
        resp = ResponseElementTree.fromXML(elem)
        self.assertIsInstance(resp, Response, 'Expecting SAML Response type')

    def test02_with_action_namespace(self):
        # Handle case where response has used an invalid namespace URI for the
        # action specified.  In the example below 'GET' is used which belongs
        # to the urn:oasis:names:tc:SAML:1.0:action:ghpp namespace.  However,
        # it has not been set so the parser should interpret it as the default
        # urn:oasis:names:tc:SAML:1.0:action:rwedc-negation -
        # 2.7.4.2 SAML 2 Core Spec. 15 March 2005
        saml_resp = '''
<samlp:Response ID="1a0c8a92-f408-4ab6-b352-dc9ae5f025cb" 
InResponseTo="d78f66ec-ddce-4a2a-81cf-6bb2bf5ea624" 
IssueInstant="2016-01-24T06:06:04.389161Z" Version="2.0" 
xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
<saml:Issuer 
Format="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName" 
xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">/C=GB/O=NDG/CN=localhost
</saml:Issuer>
<samlp:Status>
<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
</samlp:Status>
<saml:Assertion ID="41aaf9d3-b637-4d54-ac7f-0b35316c4558" 
IssueInstant="2016-01-24T06:06:04.586012Z" Version="2.0" 
xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
<saml:Issuer 
Format="urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName">
/C=GB/O=NDG/CN=localhost
</saml:Issuer>
<saml:Subject>
<saml:NameID Format="urn:esg:openid" /></saml:Subject>
<saml:Conditions NotBefore="2016-01-24T06:06:04.586012Z" 
NotOnOrAfter="2016-01-25T06:06:04.586012Z" />
<saml:AuthzDecisionStatement Decision="Deny" 
Resource="http://localhost:8000/resource.html" >
<saml:Action Namespace="urn:oasis:names:tc:SAML:1.0:action:ghpp">GET
</saml:Action>
</saml:AuthzDecisionStatement>
</saml:Assertion></samlp:Response>
'''
        authz_decision_response_stream = StringIO()
        authz_decision_response_stream.write(saml_resp)
        authz_decision_response_stream.seek(0)

        tree = ElementTree.parse(authz_decision_response_stream)
        elem = tree.getroot()
        resp = ResponseElementTree.fromXML(elem)
        self.assertIsInstance(resp, Response, 'Expecting SAML Response type')
        
    def test03_serialize_authz_decision_query(self):
        samlUtil = SAMLUtil()
        authzDecisionQuery = samlUtil.buildAuthzDecisionQuery()
        
        # Create ElementTree Assertion Element
        authzDecisionQueryElem = AuthzDecisionQueryElementTree.toXML(
                                                            authzDecisionQuery)
        
        self.assertTrue(ElementTree.iselement(authzDecisionQueryElem))
        
        # Serialise to output 
        xmlOutput = prettyPrint(authzDecisionQueryElem)       
        self.assertTrue(len(xmlOutput))
        
        print(("\n"+"_"*80))
        print(xmlOutput)
        print(("_"*80))
   
    def test04_deserialize_authz_decision_query(self):
        samlUtil = SAMLUtil()
        authzDecisionQuery = samlUtil.buildAuthzDecisionQuery()
        
        # Create ElementTree Assertion Element
        authzDecisionQueryElem = AuthzDecisionQueryElementTree.toXML(
                                                            authzDecisionQuery)
        
        self.assertTrue(ElementTree.iselement(authzDecisionQueryElem))
        
        # Serialise to output 
        xmlOutput = prettyPrint(authzDecisionQueryElem)       
        self.assertTrue(len(xmlOutput))
        
        authzDecisionQueryStream = StringIO()
        authzDecisionQueryStream.write(xmlOutput)
        authzDecisionQueryStream.seek(0)

        tree = ElementTree.parse(authzDecisionQueryStream)
        elem2 = tree.getroot()
        
        authzDecisionQuery2 = AuthzDecisionQueryElementTree.fromXML(elem2)
        self.assertTrue(authzDecisionQuery2)
        self.assertTrue(
        authzDecisionQuery2.subject.nameID.value == SAMLUtil.NAMEID_VALUE)
        self.assertTrue(
        authzDecisionQuery2.subject.nameID.format == SAMLUtil.NAMEID_FORMAT)
        self.assertTrue(
            authzDecisionQuery2.issuer.value == SAMLUtil.ISSUER_DN)
        self.assertTrue(
            authzDecisionQuery2.resource == SAMLUtil.RESOURCE_URI)
        self.assertTrue(len(authzDecisionQuery2.actions) == 1)
        self.assertTrue(
            authzDecisionQuery2.actions[0].value == Action.HTTP_GET_ACTION)
        self.assertTrue(
            authzDecisionQuery2.actions[0].namespace == Action.GHPP_NS_URI)
        self.assertTrue(authzDecisionQuery2.evidence is None)
        
#     def _create_authz_decision_query(self):
#         authzDecisionQuery = AuthzDecisionQuery()
# 
#         authzDecisionQuery.version = SAMLVersion(SAMLVersion.VERSION_20)
#         authzDecisionQuery.id = str(uuid4())
#         authzDecisionQuery.issueInstant = datetime.utcnow()
#         
#         authzDecisionQuery.issuer = Issuer()
#         authzDecisionQuery.issuer.format = Issuer.X509_SUBJECT
#         authzDecisionQuery.issuer.value = SAMLTestCase.ISSUER_DN
#         
#         authzDecisionQuery.subject = Subject()
#         authzDecisionQuery.subject.nameID = NameID()
#         authzDecisionQuery.subject.nameID.format = SAMLTestCase.NAMEID_FORMAT
#         authzDecisionQuery.subject.nameID.value = SAMLTestCase.NAMEID_VALUE
#         
#         authzDecisionQuery.resource = "http://LOCALHOST:80/My Secured URI"
#         
#         return authzDecisionQuery
         
    def _serialize_authz_decision_query_response(self):
        response = SAMLUtil.create_authz_decision_query_response()
        
        # Create ElementTree Assertion Element
        responseElem = ResponseElementTree.toXML(response)
        self.assertTrue(ElementTree.iselement(responseElem))
        
        # Serialise to output        
        xmlOutput = prettyPrint(responseElem)
        return xmlOutput
    
    def test05_serialize_authz_decision_response(self):
        xmlOutput = self._serialize_authz_decision_query_response()
        self.assertTrue(len(xmlOutput))
        print(("\n"+"_"*80))
        print(xmlOutput)
        print(("_"*80))
        
        self.assertTrue('AuthzDecisionStatement' in xmlOutput)
        self.assertTrue('GET' in xmlOutput)
        self.assertTrue('Permit' in xmlOutput)

    def test06_deserialize_authz_decision_response(self):
        xmlOutput = self._serialize_authz_decision_query_response()
        
        authzDecisionResponseStream = StringIO()
        authzDecisionResponseStream.write(xmlOutput)
        authzDecisionResponseStream.seek(0)

        tree = ElementTree.parse(authzDecisionResponseStream)
        elem = tree.getroot()
        response = ResponseElementTree.fromXML(elem)
        
        self.assertTrue(response.assertions[0])
        self.assertTrue(response.assertions[0].authzDecisionStatements[0])
        self.assertTrue(response.assertions[0].authzDecisionStatements[0
            ].decision == DecisionType.PERMIT)
        self.assertTrue(response.assertions[0].authzDecisionStatements[0
            ].resource == SAMLUtil.RESOURCE_URI)
        self.assertTrue(response.assertions[0].authzDecisionStatements[0
            ].decision == DecisionType.PERMIT)
        self.assertTrue(response.assertions[0].authzDecisionStatements[0
            ].actions[-1].namespace == Action.GHPP_NS_URI)
        self.assertTrue(response.assertions[0].authzDecisionStatements[0
            ].actions[-1].value == Action.HTTP_GET_ACTION)
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
