#!/usr/bin/env python
"""Unit tests for WSGI SAML 2.0 SOAP Attribute Query Interface

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "03/11/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import unittest

from datetime import timedelta
from ndg.saml.saml2.binding.soap.server.wsgi.queryinterface import \
    SOAPQueryInterfaceMiddleware
    
from ndg.saml.xml.etree import AttributeQueryElementTree    
from ndg.saml.xml.etree import ResponseElementTree


class SOAPQueryInterfaceMiddlewareTestCase(unittest.TestCase):
    """Test Setting of SOAP Query Interface middleware attributes"""
        
    def test01Create(self):
        queryIface = SOAPQueryInterfaceMiddleware(None)
        config = {
        'mountPath': '/attribute-authority',
        'queryInterfaceKeyName': 'QUERY_IFACE_KEY',
        'deserialise': 'ndg.saml.xml.etree:AttributeQueryElementTree.fromXML',
        'serialise': 'ndg.saml.xml.etree:ResponseElementTree.toXML',
        'clockSkewTolerance': 60*3       
        }
        queryIface.initialise({}, **config)
        self.assertTrue(queryIface.mountPath == '/attribute-authority')
        self.assertTrue(queryIface.queryInterfaceKeyName == 'QUERY_IFACE_KEY')
        self.assertTrue(queryIface.deserialise == \
                     AttributeQueryElementTree.fromXML)
        self.assertTrue(queryIface.serialise == ResponseElementTree.toXML)
        self.assertTrue(queryIface.clockSkewTolerance == timedelta(seconds=60*3))


if __name__ == "__main__":
    unittest.main()
