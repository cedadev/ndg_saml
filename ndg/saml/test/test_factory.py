'''
Created on 16 Jul 2015

@author: philipkershaw
'''
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
        
    def test02_from_config(self):
        attribute_query = AttributeQueryFactory.from_config(
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