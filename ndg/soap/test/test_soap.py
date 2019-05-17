#!/usr/bin/env python
"""SOAP module unit test module

NERC DataGrid Project
"""
from ndg.saml.test.binding.soap import paste_installed
__author__ = "P J Kershaw"
__date__ = "24/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
import logging
logging.basicConfig(level=logging.DEBUG)

import unittest
from io import StringIO
from os import path
from urllib.request import HTTPHandler, URLError

try:
    import paste.fixture
    paste_installed = True
except ImportError:
    paste_installed = False
    
from ndg.soap import SOAPFaultBase
from ndg.soap.etree import SOAPEnvelope, SOAPFault, SOAPFaultException
from ndg.soap.client import SOAPClient, SOAPRequest


class SOAPBindingMiddleware(object):
    """Simple WSGI interface for SOAP service"""
        
    def __call__(self, environ, start_response):
        requestFile = environ['wsgi.input']
        
        print(("Server received request from client:\n\n%s" % 
              requestFile.read()))
        
        soapResponse = SOAPEnvelope()
        soapResponse.create()
        
        response = soapResponse.serialize()
        start_response("200 OK",
                       [('Content-length', str(len(response))),
                        ('Content-type', 'text/xml')])
        return [response]
    
    
class SOAPTestCase(unittest.TestCase):
    EG_SOAPFAULT_CODE = "{}:{}".format(SOAPFaultBase.DEFAULT_ELEMENT_NS_PREFIX, 
                                       "MustUnderstand")
    EG_SOAPFAULT_STRING = "Can't process element X set with mustUnderstand"
        
    def test01Envelope(self):
        envelope = SOAPEnvelope()
        envelope.create()
        soap = envelope.serialize().decode()
        
        self.assertTrue(len(soap) > 0)
        self.assertTrue("Envelope" in soap)
        self.assertTrue("Body" in soap)
        self.assertTrue("Header" in soap)
        
        print((envelope.prettyPrint()))
        stream = StringIO()
        stream.write(soap)
        stream.seek(0)
        
        envelope2 = SOAPEnvelope()
        envelope2.parse(stream)
        soap2 = envelope2.serialize().decode()
        self.assertTrue(soap2 == soap)

    def test02CreateSOAPFaultBase(self):
        
        fault = SOAPFaultBase(self.__class__.EG_SOAPFAULT_STRING, 
                              self.__class__.EG_SOAPFAULT_CODE)
        
        self.assertTrue(
            fault.faultCode == self.__class__.EG_SOAPFAULT_CODE)
        self.assertTrue(
            fault.faultString == self.__class__.EG_SOAPFAULT_STRING)
     
    def _createSOAPFault(self):
        fault = SOAPFault(self.__class__.EG_SOAPFAULT_STRING, 
                          self.__class__.EG_SOAPFAULT_CODE)
        fault.create()
        return fault   
    
    def test03SerialiseSOAPFault(self):
        # Use ElementTree implementation
        fault = self._createSOAPFault()
        faultStr = fault.serialize().decode()
        print(faultStr)
        self.assertTrue(self.__class__.EG_SOAPFAULT_STRING in faultStr)

    def test04ParseSOAPFault(self):
        fault = self._createSOAPFault()
        faultStr = fault.serialize().decode()
        stream = StringIO()
        stream.write(faultStr)
        stream.seek(0)
        
        fault2 = SOAPFault()
        fault2.parse(stream)
        self.assertTrue(fault2.faultCode == fault.faultCode)
        self.assertTrue(fault2.faultString == fault.faultString)
    
    def test05CreateSOAPFaultException(self):
        try:
            raise SOAPFaultException("bad request", 
                                     SOAPFault.CLIENT_FAULT_CODE)
        
        except SOAPFaultException as e:
            self.assertTrue(e.fault.faultString == "bad request")
            self.assertTrue(SOAPFault.CLIENT_FAULT_CODE in e.fault.faultCode)
            e.fault.create()
            self.assertTrue("bad request" in e.fault.serialize().decode())
            self.assertTrue(
                SOAPFault.CLIENT_FAULT_CODE in e.fault.serialize().decode())
            return
        
        self.fail("Expecting SOAPFaultException raised")
        
    def test06CreateSOAPFaultResponse(self):
        # Create full SOAP Response containing a SOAP Fault
        envelope = SOAPEnvelope()
        envelope.body.fault = self._createSOAPFault()
        envelope.create()
        
        # Convert to unicode for tests
        soap = envelope.serialize().decode()
        
        self.assertTrue(len(soap) > 0)
        self.assertTrue("Envelope" in soap)
        self.assertTrue("Body" in soap)
        self.assertTrue("Header" in soap)
        self.assertTrue("Fault" in soap)
        
        print((envelope.prettyPrint()))
        stream = StringIO()
        stream.write(soap)
        stream.seek(0)
        
        envelope2 = SOAPEnvelope()
        envelope2.parse(stream)
        soap2 = envelope2.serialize().decode()
        self.assertTrue(soap2 == soap)
            

_TEST_SOAP_SERVICE_PORTNUM = 10080
_TEST_SOAP_SERVICE_ENDPOINT = 'http://localhost:{}/soap'.format(
    _TEST_SOAP_SERVICE_PORTNUM)

def _is_soap_server_running():
    '''Helper function to ensure SOAP server is running for 
    SOAPServiceTestCase client test
    '''
    import urllib
    try:
        urllib.request.urlopen(_TEST_SOAP_SERVICE_ENDPOINT)
    except Exception as e:
        import warnings
        warnings.warn("Error calling test soap server {}".format(e))
        return False
    
    return True

class SOAPServiceTestCase(unittest.TestCase):
    ENDPOINT = _TEST_SOAP_SERVICE_ENDPOINT
    THIS_DIR = path.abspath(path.dirname(__file__))   
    
    @unittest.skipIf(not paste_installed, 'Need Paste.Deploy to run '
                     'SOAPServiceTestCase')
    
    def __init__(self, *args, **kwargs):
        """Use paste.fixture to test client/server SOAP interface"""
        self.services = []
        self.disableServiceStartup = False

        wsgiApp = SOAPBindingMiddleware()
        self.app = paste.fixture.TestApp(wsgiApp)
         
        super(SOAPServiceTestCase, self).__init__(*args, **kwargs)
             
    def test01SendRequest(self):
        requestEnvelope = SOAPEnvelope()
        requestEnvelope.create()
        request = requestEnvelope.serialize()
        
        response = self.app.post('/my-soap-endpoint', 
                                 params=request, 
                                 status=200)
        print((response.headers))
        print((response.status))
        print((response.body))
    
    @unittest.skipIf(not _is_soap_server_running(), 
                     '"/ndg_saml/ndg/soap/test/soap_server.py" must be '
                    "running in order to enable this test")
    def test02_client(self):
        
        client = SOAPClient()
        
        # ElementTree based envelope class
        client.responseEnvelopeClass = SOAPEnvelope
        
        request = SOAPRequest()
        request.url = self.__class__.ENDPOINT
        request.envelope = SOAPEnvelope()
        request.envelope.create()
        
        client.openerDirector.add_handler(HTTPHandler())
        try:
            response = client.send(request)
        except URLError:
            self.fail("\"/ndg_saml/ndg/soap/test/soap_server.py\" must be "
                      "running for this test")
        
        print(("Response from server:\n\n%s" % response.envelope.serialize()))


if __name__ == "__main__":
    unittest.main()
