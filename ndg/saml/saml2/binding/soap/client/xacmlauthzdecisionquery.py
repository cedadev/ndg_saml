"""SAML 2.0 bindings module implements SOAP binding for XACMLAuthzDecisionQuery

NERC DataGrid Project
"""
__author__ = "R B Wilkinson"
__date__ = "23/12/11"
__copyright__ = "Copyright 2019 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from urllib.parse import urlparse
import logging
log = logging.getLogger(__name__)

from ndg.httpsclient.https import HTTPSContextHandler as HTTPSHandler_

from ndg.saml.saml2.binding.soap.client.requestbase import \
                                                        RequestBaseSOAPBinding
from ndg.saml.saml2.xacml_profile import XACMLAuthzDecisionQuery

# Prevent whole module breaking if this is not available - it's only needed for
# XACMLAuthzDecisionQuerySslSOAPBinding
from ndg.saml.utils.pyopenssl import SSLContextProxy as SSLContextProxy_


class XACMLAuthzDecisionQuerySOAPBinding(RequestBaseSOAPBinding):
    """XACML-SAML Attribute Query SOAP Binding
    
    Nb. Assumes X.509 subject type for query issuer
    """
    SERIALISE_KW = 'serialise'
    DESERIALISE_KW = 'deserialise'
    QUERY_TYPE = XACMLAuthzDecisionQuery
    __slots__ = ()

    def __init__(self, **kw):
        '''Create SOAP Client for SAML Authorization Decision Query'''
        cls = XACMLAuthzDecisionQuerySOAPBinding

        # Default to ElementTree based serialisation/deserialisation
        if cls.SERIALISE_KW not in kw:
            from ndg.saml.xml.etree_xacml_profile \
                import XACMLAuthzDecisionQueryElementTree
            kw[cls.SERIALISE_KW] = XACMLAuthzDecisionQueryElementTree.toXML

        if cls.DESERIALISE_KW not in kw:
            from ndg.saml.xml.etree import ResponseElementTree
            kw[cls.DESERIALISE_KW] = ResponseElementTree.fromXML

        super(XACMLAuthzDecisionQuerySOAPBinding, self).__init__(**kw)


# Copied from AuthzDecisionQuerySslSOAPBinding
class XACMLAuthzDecisionQuerySslSOAPBinding(XACMLAuthzDecisionQuerySOAPBinding):
    """Specialisation of AuthzDecisionQuerySOAPbinding taking in the setting of
    SSL parameters for mutual authentication
    """
    __slots__ = ('__sslCtxProxy',)
    
    def __init__(self, **kw):
        # Miss out default HTTPSHandler and set in send() instead
        if 'handlers' in kw:
            raise TypeError("__init__() got an unexpected keyword argument "
                            "'handlers'")
            
        super(XACMLAuthzDecisionQuerySslSOAPBinding, self).__init__(
                                                            handlers=(), **kw)
        self.__sslCtxProxy = SSLContextProxy_()

    def send(self, query, **kw):
        """Override base class implementation to pass explicit SSL Context
        """
        if 'uri' in kw:
            parsed_url = urlparse(kw['uri'])
            self.sslCtxProxy.ssl_valid_hostname = parsed_url.netloc.split(':'
                                                                          )[0]
                                                                          
        httpsHandler = HTTPSHandler_(ssl_context=self.sslCtxProxy())
        self.client.openerDirector.add_handler(httpsHandler)
        return super(XACMLAuthzDecisionQuerySslSOAPBinding, self).send(query, 
                                                                       **kw)
        
    @property
    def sslCtxProxy(self):
        """SSL Context Proxy object used for setting up an SSL Context for
        queries
        """
        return self.__sslCtxProxy
            
    def __setattr__(self, name, value):
        """Enable setting of SSLContextProxy attributes as if they were 
        attributes of this class.  This is intended as a convenience for 
        making settings parameters read from a config file
        """
        try:
            super(XACMLAuthzDecisionQuerySslSOAPBinding, self).__setattr__(name, 
                                                                        value)
            
        except AttributeError as e:
            # Coerce into setting SSL Context Proxy attributes
            try:
                setattr(self.sslCtxProxy, name, value)
            except:
                raise e
