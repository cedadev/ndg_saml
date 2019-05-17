"""SOAP client module for NDG SAML - for use with SAML SOAP binding 

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "27/07/09"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
from abc import ABC, abstractmethod
import http.client
import urllib

import logging
log = logging.getLogger(__name__)

from ndg.soap import SOAPEnvelopeBase


class SOAPClientError(Exception):
    """Base class for SOAP Client exceptions"""


class SOAPParseError(SOAPClientError):
    """Error parsing SOAP response"""
    
           
class SOAPClientBase(ABC):
    """Handle client request to a SOAP Service
    @cvar RESPONSE_CONTENT_TYPES: expected content type to be returned in a 
    response from a service
    @type RESPONSE_CONTENT_TYPES: string
    """
    RESPONSE_CONTENT_TYPES = ('text/xml', )
    
    def __init__(self):
        self.__responseEnvelopeClass = None

    def _getResponseEnvelopeClass(self):
        return self.__responseEnvelopeClass

    def _setResponseEnvelopeClass(self, value):
        if not issubclass(value, SOAPEnvelopeBase):
            raise TypeError("Setting SOAP envelope class: expecting %r, got "
                            "%r" % (SOAPEnvelopeBase, type(value)))
        self.__responseEnvelopeClass = value

    responseEnvelopeClass = property(fget=_getResponseEnvelopeClass, 
                                     fset=_setResponseEnvelopeClass, 
                                     doc="Set the class for handling "
                                         "the SOAP envelope responses")
    
    @abstractmethod 
    def send(self, soapRequest):
        raise NotImplementedError()


class _SoapIOBase(object):
    """Base class for request and response classes"""
    
    def __init__(self):
        self.__envelope = None

    def _getEnvelope(self):
        return self.__envelope

    def _setEnvelope(self, value):
        if not isinstance(value, SOAPEnvelopeBase):
            raise TypeError('Setting SOAP envelope object: expecting %r; got '
                            '%r' % (SOAPEnvelopeBase, type(value)))
                            
        self.__envelope = value

    envelope = property(fget=_getEnvelope, 
                        fset=_setEnvelope, 
                        doc="SOAP Envelope object used in request/response")

        
class SOAPRequestBase(object):
    """Interface for SOAP requests"""
    def __init__(self):
        self.__url = None
        self.__envelope = None

    def _getUrl(self):
        return self.__url

    def _setUrl(self, value):
        if not isinstance(value, str):
            raise TypeError('Setting request URL: expecting %r; got '
                            '%r' % (str, type(value)))
        self.__url = value

    url = property(fget=_getUrl, fset=_setUrl, doc="URL of SOAP endpoint")

   
class SOAPResponseBase(_SoapIOBase):
    """Interface for SOAP responses"""


class SOAPClientResponseError(SOAPClientError):
    """Specialisation to enable the urllib response to be included in the
    exception instance as context information for the caller
    """
    RESPONSE_TYPE = http.client.HTTPResponse
    
    def __init__(self, *arg, **kw):
        Exception.__init__(self, *arg, **kw)
        self.__response = None

    @property
    def response(self):
        return self.__response

    @response.setter
    def response(self, value):
        if not isinstance(value, SOAPClientError.RESPONSE_TYPE):
            raise TypeError('Expecting %r type for "urllib2Response"; '
                            'got %r'.format(SOAPClientError.RESPONSE_TYPE, 
                                            type(value)))
        self.__response = value


class SOAPResponseError(SOAPClientError):
    """Raise for invalid SOAP response from server"""
     
       
class HTTPException(SOAPClientError):
    """Server returned HTTP code error code"""


class SOAPRequest(SOAPRequestBase):  
    """Interface for based SOAP Requests"""
    
    
class SOAPResponse(SOAPResponseBase):
    """Interface for based SOAP Responses"""
    def __init__(self):
        self.__fileobject = None
        
    @property
    def fileobject(self):
        "urllib2 file object returned from request"
        return self.__fileobject


class CapitalizedKeysDict(dict):
    """Extend dict type to make keys capitalized.  Keys must be string type"""
    def __init__(self, *arg, **kw):
        if len(arg) > 0:
            arg = list(arg)
            
            if isinstance(arg[0], dict):
                arg[0] = [(k.capitalize(), v) for k, v in list(arg[0].items())]
            else:
                arg[0] = [(k.capitalize(), v) for k, v in arg[0]] 
                
            arg = tuple(arg)
        
        kw = dict([(k.capitalize(), v) for k, v in list(kw.items())])
        
        super(CapitalizedKeysDict, self).__init__(*arg, **kw)
        
    def __setitem__(self, k, v):
        if not isinstance(k, str):
            raise TypeError('Key must be string type; got %r' % type(k))
        
        super(CapitalizedKeysDict, self).__setitem__(k.capitalize(), v)
     
    def copy(self):
        """Explicit copy implementation to ensure CapitalizedKeysDict return 
        type"""
        return CapitalizedKeysDict(self)
    
    
class SOAPClient(SOAPClientBase):
    """urllib2 based SOAP Client"""
    DEFAULT_HTTP_HEADER = CapitalizedKeysDict({'Content-type': 'text/xml'})
    
    def __init__(self):
        super(SOAPClient, self).__init__()
        self.__openerDirector = urllib.request.OpenerDirector()
        self.__openerDirector.add_handler(urllib.request.UnknownHandler())
        self.__openerDirector.add_handler(urllib.request.HTTPHandler())
        self.__timeout = None
        self.__httpHeader = SOAPClient.DEFAULT_HTTP_HEADER.copy()

    @property
    def httpHeader(self):
        "Set HTTP header fields in this dict object"
        return self.__httpHeader

    def _getSOAPAction(self):
        return self.__httpHeader.get('Soapaction')

    def _setSOAPAction(self, value):
        if not isinstance(value, str):
            raise TypeError("Setting request soapAction: got %r, expecting "
                            "string type" % type(value))
        self.__httpHeader['Soapaction'] = value
        
    soapAction = property(fget=_getSOAPAction, 
                          fset=_setSOAPAction, 
                          doc="SOAPAction HTTP header field setting") 
       
    def _getTimeout(self):
        return self.__timeout

    def _setTimeout(self, value):
        if not isinstance(value, (int, float)):
            raise TypeError("Setting request timeout: got %r, expecting int "
                            "or float type" % type(value))
        self.__timeout = value

    timeout = property(fget=_getTimeout, 
                       fset=_setTimeout, 
                       doc="Timeout (seconds) for requests")

    def _getOpenerDirector(self):
        return self.__openerDirector

    def _setOpenerDirector(self, value):
        """This shouldn't need to be used much in practice because __init__
        creates one"""
        if not isinstance(value, urllib.request.OpenerDirector):
            raise TypeError("Setting opener: expecting %r; got %r" % 
                            (urllib.request.OpenerDirector, type(value)))
        self.__openerDirector = value

    openerDirector = property(fget=_getOpenerDirector, 
                              fset=_setOpenerDirector, 
                              doc="urllib2.OpenerDirector defines the "
                                  "opener(s) for handling requests")
    
    def send(self, soapRequest):
        """Make a request to the given URL with a SOAP Request object"""
        
        if not isinstance(soapRequest, SOAPRequest):
            raise TypeError('SOAPClient.send: expecting %r '
                            'derived type for SOAP request, got %r' % 
                            (self.responseEnvelopeClass, type(soapRequest)))
            
        if not isinstance(soapRequest.envelope, self.responseEnvelopeClass):
            raise TypeError('SOAPClient.send: expecting %r '
                            'derived type for SOAP envelope, got %r' % 
                            (self.responseEnvelopeClass, type(soapRequest)))
                            
        if self.timeout is not None:
            arg = (self.timeout,)
        else:
            arg = ()
            
        soapRequestStr = soapRequest.envelope.serialize()

        logLevel = log.getEffectiveLevel()
        if logLevel <= logging.DEBUG:
            from ndg.soap.utils.etree import prettyPrint
            log.debug("SOAP Request:")
            log.debug("_"*80)
            log.debug(prettyPrint(soapRequest.envelope.elem))

        soapResponse = SOAPResponse()
        urllib2Request = urllib.request.Request(soapRequest.url) 
        for i in list(self.httpHeader.items()):
            urllib2Request.add_header(*i)
            
        response = self.openerDirector.open(urllib2Request, 
                                            soapRequestStr, 
                                            *arg)
        if response.code != http.client.OK:
            excep = HTTPException("Response for request to [%s] is: %d %s" % 
                                  (soapRequest.url, 
                                   response.code, 
                                   response.msg))
            excep.urllib2Response = response
            raise excep
        
        # Check for accepted response type string in response from server
        accepted_response_content_type = False
        for content_type in SOAPClient.RESPONSE_CONTENT_TYPES:
            if content_type in response.headers.values():
                accepted_response_content_type = True
        
        if not accepted_response_content_type:
            responseType = ', '.join(SOAPClient.RESPONSE_CONTENT_TYPES)
            excep = SOAPResponseError("Expecting %r response type; got %r for "
                                      "request to [%s]" % 
                                      (responseType, 
                                       response.headers.get_content_type(),
                                       soapRequest.url))
            excep.urllib2Response = response
            raise excep
            
        soapResponse.fileObject = response
        soapResponse.envelope = self.responseEnvelopeClass()  
        
        try:
            soapResponse.envelope.parse(soapResponse.fileObject)
        except Exception as e:
            raise SOAPParseError("%r type error raised parsing response for "
                                 "request to [%s]: %s"
                                 % (type(e), soapRequest.url, e))
        
        if logLevel <= logging.DEBUG:
            log.debug("SOAP Response:")
            log.debug("_"*80)
            log.debug(prettyPrint(soapResponse.envelope.elem))
            
        return soapResponse
