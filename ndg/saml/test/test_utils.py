'''
Created on 16 Jul 2015

@author: philipkershaw
'''
import unittest

from ndg.saml.utils.config import AttributeQueryConfig


class AttributeQueryConfigTestCase(unittest.TestCase):

    def setUp(self):
        self.config = {
            'attributeQuery.subject.nameID.format': 'urn:esg:openid',
            'attributeQuery.issuer.value': '/O=Site A/CN=Authorisation Service',
            'attributeQuery.attributes.0': 
    'urn:esg:first:name, FirstName, http://www.w3.org/2001/XMLSchema#string',
            'attributeQuery.attributes.roles': 
'urn:siteA:security:authz:1.0:attr, , http://www.w3.org/2001/XMLSchema#string'  
        }
        
    def test01(self):
        config = AttributeQueryConfig(prefix='attributeQuery.')
        config.parse(**self.config)
        
        self.assertEqual(config.attribute_query.subject.nameID.format, 
                         self.config['attributeQuery.subject.nameID.format'], 
                         'Parameter is %r, expected %r' % (
                          config.attribute_query.subject.nameID.format, 
                          self.config['attributeQuery.subject.nameID.format']))
        
        self.assertEqual(config.attribute_query.issuer.value, 
                         self.config['attributeQuery.issuer.value'], 
                         'Parameter is %r, expected %r' % (
                         config.attribute_query.issuer.value, 
                         self.config['attributeQuery.issuer.value']))
        
        attr = config.attribute_query.attributes[0]                    
        self.assertIn(attr.nameFormat, 
                      self.config['attributeQuery.attributes.0'], 
                      'Parameter is %r, expected %r' % (
                          attr.nameFormat, 
                          self.config['attributeQuery.attributes.0']))

        self.assertIn(attr.name, 
                      self.config['attributeQuery.attributes.0'], 
                      'Parameter is %r, expected %r' % (
                          attr.name, 
                          self.config['attributeQuery.attributes.0']))


if __name__ == "__main__":
    unittest.main()