'''SAML factory module unit test package


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
'''
__author__ = "P J Kershaw"
__date__ = "16/07/15"
__copyright__ = "(C) 2015 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import unittest

from ndg.saml.utils.factory import AttributeQueryFactory


class FactoryTestCase(unittest.TestCase):
    '''Test factory classes'''
    def setUp(self):
        self.config = {
            'attributeQuery.subject.nameID.format': 'urn:esg:openid',
            'attributeQuery.issuer.value': '/O=Site A/CN=Authorisation Service',
            'attributeQuery.attributes.0': 
    'urn:esg:first:name, FirstName, http://www.w3.org/2001/XMLSchema#string',
            'attributeQuery.attributes.roles': 
'urn:siteA:security:authz:1.0:attr, , http://www.w3.org/2001/XMLSchema#string'  
        }
        
    def test01_create(self):
        attribute_query = AttributeQueryFactory.create()
        self.assertIsNotNone(attribute_query.subject, 'query subject is none')
        self.assertIsNotNone(attribute_query.issuer, 'query issuer is none')
        
    def test02_from_kw(self):
        attribute_query = AttributeQueryFactory.from_kw(
                                                    prefix='attributeQuery.',
                                                    **self.config)
        
        self.assertEqual(attribute_query.subject.nameID.format, 
                         self.config['attributeQuery.subject.nameID.format'], 
                         'Parameter is %r, expected %r' % (
                          attribute_query.subject.nameID.format, 
                          self.config['attributeQuery.subject.nameID.format']))
        
        self.assertEqual(attribute_query.issuer.value, 
                         self.config['attributeQuery.issuer.value'], 
                         'Parameter is %r, expected %r' % (
                         attribute_query.issuer.value, 
                         self.config['attributeQuery.issuer.value']))
        
        self.assertEqual(len(attribute_query.attributes), 2, 
                        'expecting 2 SAML attributes parsed')
        
        attr = None
        for attr in attribute_query.attributes:
            if attr.friendlyName == 'FirstName':
                break
            
        self.assertNotEqual(attr, None, 
                            'Missing expected friendlyName attribute')
                           
        self.assertIn(attr.nameFormat, 
                      self.config['attributeQuery.attributes.0'], 
                      'Parameter is %r, not found in %r' % (
                          attr.nameFormat, 
                          self.config['attributeQuery.attributes.0']))

        self.assertIn(attr.name, 
                      self.config['attributeQuery.attributes.0'], 
                      'Parameter is %r, not found in %r' % (
                          attr.name, 
                          self.config['attributeQuery.attributes.0']))


if __name__ == "__main__":
    unittest.main()