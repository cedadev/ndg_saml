"""SAML SOAP Binding Query/Response Interface with service hosted in
Gunicorn WSGI server

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "01/07/10"
__copyright__ = "Copyright 2019 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
import logging
logging.basicConfig(level=logging.DEBUG)

import unittest
from os import path
from urllib.error import URLError

from ndg.saml import importElementTree
ElementTree = importElementTree()

from ndg.soap.utils.etree import prettyPrint

from ndg.saml.saml2.core import Attribute, StatusCode
from ndg.saml.xml.etree import ResponseElementTree
from ndg.saml.saml2.binding.soap.client.attributequery import \
    AttributeQuerySslSOAPBinding
from ndg.saml.utils.factory import AttributeQueryFactory
from ndg.saml.test.binding.soap import paste_installed
    

_THIS_DIR = path.dirname(__file__)
_TEST_ATTRIBUTE_SERVICE_STEM_URI = 'https://localhost:5443/'
_TEST_ATTRIBUTE_SERVICE_URI = _TEST_ATTRIBUTE_SERVICE_STEM_URI + \
                                'attribute-service'
_TEST_ATTRIBUTE_SERVICE_CACERT_DIR = path.join(_THIS_DIR, 'ca')

def _is_attribute_service_running():
    '''Helper function to ensure SAML Attribute service is running for 
    SamlSslSoapBindingTestCase client test
    '''
    import urllib
    
    exception = None
    
    try:
        urllib.request.urlopen(_TEST_ATTRIBUTE_SERVICE_URI, 
                               capath=_TEST_ATTRIBUTE_SERVICE_CACERT_DIR)
    except urllib.error.HTTPError as e:
        # Expecting 400 response with GET request.  Correct method is POST
        # but GET is sufficient to sanity check that the service is up
        if e.code != 400:
            exception = e
            
    except Exception as e:
        exception = e
        
    if exception:
        import warnings
        warnings.warn("Error calling test attribute service "
                      "{}".format(exception))
        return False
    else:
        return True


          
class SamlSslSoapBindingTestCase(unittest.TestCase):
    """Test SAML SOAP Binding with SSL"""
    SERVICE_URI = _TEST_ATTRIBUTE_SERVICE_URI
    SUBJECT = "https://openid.localhost/philip.kershaw"
    SUBJECT_FORMAT = "urn:ndg:saml:openid"
    CONFIG_FILENAME = 'attribute-interface.ini'
    
    THIS_DIR = _THIS_DIR
    CLIENT_CERT_FILEPATH = path.join(THIS_DIR, 'localhost.crt')
    CLIENT_PRIKEY_FILEPATH = path.join(THIS_DIR, 'localhost.key')
    CLIENT_CACERT_DIR = _TEST_ATTRIBUTE_SERVICE_CACERT_DIR
    VALID_DNS = [
        '/O=NDG/OU=Security/CN=localhost', 
    ]
    
    @unittest.skipIf(not paste_installed, 'Need Paste.Deploy to run '
                     'SamlSslSoapBindingTestCase')
    
    @unittest.skipIf(not _is_attribute_service_running(), 
                     '"{}" must be running in order to enable this '
                     'test'.format(path.join(THIS_DIR, 
                                             'attribute_service_runner.py')))
    
    def test01_send_query(self):
        query_binding = AttributeQuerySslSOAPBinding()
        
        attribute_query = AttributeQueryFactory.create()
        attribute_query.subject.nameID.format = self.__class__.SUBJECT_FORMAT
        attribute_query.subject.nameID.value = self.__class__.SUBJECT
        attribute_query.issuer.value = '/O=Site A/CN=Authorisation Service'


        attribute = Attribute()
        attribute.name = 'urn:ndg:saml:emailaddress'
        attribute.friendlyName = 'emailAddress'
        attribute.nameFormat = 'http://www.w3.org/2001/XMLSchema'
        
        attribute_query.attributes.append(attribute)
        
        query_binding.clockSkewTolerance = 2.
        query_binding.sslCACertDir = self.__class__.CLIENT_CACERT_DIR
        query_binding.sslCertFilePath = self.__class__.CLIENT_CERT_FILEPATH
        query_binding.sslPriKeyFilePath = self.__class__.CLIENT_PRIKEY_FILEPATH
        query_binding.sslValidDNs = self.__class__.VALID_DNS
        
        try:
            response = query_binding.send(attribute_query, 
                                          uri=self.__class__.SERVICE_URI)
        except URLError:
            import warnings
            warnings.warn("Check that the test Attribute Service is running. "
                          " Run attribute_service_runner.py")
            raise
        
        # Convert back to ElementTree instance read for string output
        samlResponseElem = ResponseElementTree.toXML(response)
        
        print("SAML Response ...")
        print((ElementTree.tostring(samlResponseElem)))
        print("Pretty print SAML Response ...")
        print((prettyPrint(samlResponseElem)))
        
        self.assertTrue(
            response.status.statusCode.value==StatusCode.SUCCESS_URI)

 
if __name__ == "__main__":
    if paste_installed:
        unittest.main()
    else:
        import warnings
        warnings.warn('Skip unittests for %r, Paste package is not installed' %
                      __name__)
