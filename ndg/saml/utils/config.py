'''
Created on 16 Jul 2015

@author: philipkershaw
'''
import re

from ndg.saml.saml2 import core as saml2


class SubjectFactory(object):
    '''Factory class to create Subject instance'''
    
    @classmethod
    def create(cls):
        '''Create a blank subject with name id instantiated
        '''
        subject = saml2.Subject()
        subject.nameID = saml2.NameID()
        
        return subject


class AttributeQueryFactory(object):
    """Factory class to create attribute queries from various inputs
    """
    PREFIX = 'attribute_query.'
    SUBJECT_PARAM_NAME_PREFIX = 'subject.'
    ISSUER_PARAM_NAME_PREFIX = 'issuer.'
    ATTR_PARAM_VAL_SEP_PAT = re.compile(',\s*')
    ATTR_PARAM_NAME_PREFIX = 'attributes.'
    
    @classmethod
    def create(cls):
        '''Create a blank attribute query with all member variables instantiated
         - issuer, subject etc.
        '''
        attribute_query = saml2.AttributeQuery()
        attribute_query.subject = SubjectFactory.create()
        attribute_query.issuer = saml2.Issuer()
    
        return attribute_query
   
    @classmethod
    def from_config(cls, prefix=PREFIX, **config):
        '''parse attribute query from an input config dictionary'''
        attribute_query = cls.create()
        pat = cls.ATTR_PARAM_VAL_SEP_PAT
        
        for param_name, param_val in config.items():
            
            # Skip values that don't start with the correct prefix
            if not param_name.startswith(prefix):
                continue
            
            _param_name = param_name.rsplit(prefix, 1)[-1]
            
            # Check for items which have the same name as AttributeQuery
            # object member variables
            if _param_name.startswith(cls.SUBJECT_PARAM_NAME_PREFIX):
                nameid_param_name = _param_name.rsplit('subject.nameID.')[-1]
                
                setattr(attribute_query.subject.nameID, nameid_param_name, 
                        param_val)
                
            elif _param_name.startswith(cls.ISSUER_PARAM_NAME_PREFIX):
                issuer_param_name = _param_name.rsplit('issuer.')[-1]
                setattr(attribute_query.issuer, issuer_param_name, 
                        param_val)
                
            elif _param_name.startswith(cls.ATTR_PARAM_NAME_PREFIX):
                # attributes are set with a special syntax.  Each attribute
                # name in the dictionary should start with 
                # ``prefix`` and end with some unique string
                attribute = saml2.Attribute()
                
                # The values should be parsed from a string containing a 
                # comma-separated list e.g.
                #
                # attribute.0 = urn:esg:first:name, FirstName, http://www.w3.org/2001/XMLSchema#string
                (attribute.name, 
                 attribute.friendlyName, 
                 attribute.nameFormat) = pat.split(param_val)
         
                attribute_query.attributes.append(attribute)
            else:
                raise AttributeError('Config item %r not recognised as a valid '
                                     'AttributeQuery object member variable.' %(
                                                                 param_name))
            
        return attribute_query
            