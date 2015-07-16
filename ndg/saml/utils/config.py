'''
Created on 16 Jul 2015

@author: philipkershaw
'''
import re

from ndg.saml.saml2.core import attribute_query_factory, Attribute


class AttributeQueryConfig(object):
    """Utility class to parse attributes from an input config dictionary
    """
    PREFIX = 'attribute_query.'
    SUBJECT_PARAM_NAME_PREFIX = 'subject.'
    ISSUER_PARAM_NAME_PREFIX = 'issuer.'
    ATTR_PARAM_VAL_SEP_PAT = re.compile(',\s*')
    ATTR_PARAM_NAME_PREFIX = 'attributes.'
    
    def __init__(self, prefix=PREFIX):
        self.prefix = prefix
        self.attribute_query = attribute_query_factory()
        
    def parse(self, **config):
        pat = self.__class__.ATTR_PARAM_VAL_SEP_PAT
        
        for param_name, param_val in config.items():
            
            # Skip values that don't start with the correct prefix
            if not param_name.startswith(self.prefix):
                continue
            
            _param_name = param_name.rsplit(self.prefix, 1)[-1]
            
            # Check for items which have the same name as AttributeQuery
            # object member variables
            if _param_name.startswith(self.__class__.SUBJECT_PARAM_NAME_PREFIX):
                nameid_param_name = _param_name.rsplit('subject.nameID.')[-1]
                
                setattr(self.attribute_query.subject.nameID, nameid_param_name, 
                        param_val)
                
            elif _param_name.startswith(
                                    self.__class__.ISSUER_PARAM_NAME_PREFIX):
                issuer_param_name = _param_name.rsplit('issuer.')[-1]
                setattr(self.attribute_query.issuer, issuer_param_name, 
                        param_val)
                
            elif _param_name.startswith(self.__class__.ATTR_PARAM_NAME_PREFIX):
                # attributes are set with a special syntax.  Each attribute
                # name in the dictionary should start with 
                # ``prefix`` and end with some unique string
                attribute = Attribute()
                
                # The values should be parsed from a string containing a 
                # comma-separated list e.g.
                #
                # attribute.0 = urn:esg:first:name, FirstName, http://www.w3.org/2001/XMLSchema#string
                (attribute.name, 
                 attribute.friendlyName, 
                 attribute.nameFormat) = pat.split(param_val)
         
                self.attribute_query.attributes.append(attribute)
            else:
                raise AttributeError('Config item %r not recognised as a valid '
                                     'AttributeQuery object member variable.' %(
                                                                 param_name))
            
    @classmethod
    def from_config(cls, prefix=PREFIX, **config):
        """Instantiate and parse input content"""
        obj = cls(prefix=prefix)
        obj.parse(**config)
        
        return obj