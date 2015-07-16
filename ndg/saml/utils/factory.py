"""
Class Factory for NDG SAML package

NERC DataGrid project
"""
__author__ = "Philip Kershaw"
__date__ = "15/02/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:$'
import traceback
import logging
import os
import sys
import re

from ndg.saml.saml2 import core as saml2

log = logging.getLogger(__name__)


def importModuleObject(moduleName, objectName=None, objectType=None):
    '''Import from a string module name and object name.  Object can be
    any entity contained in a module
    
    @param moduleName: Name of module containing the class
    @type moduleName: str 
    @param objectName: Name of the class to import.  If none is given, the 
    class name will be assumed to be the last component of modulePath
    @type objectName: str
    @rtype: class object
    @return: imported class'''
    if objectName is None:
        if ':' in moduleName:
            # Support Paste style import syntax with rhs of colon denoting 
            # module content to import
            _moduleName, objectName = moduleName.rsplit(':', 1)
            if '.' in objectName:
                objectName = objectName.split('.')
        else: 
            try:
                _moduleName, objectName = moduleName.rsplit('.', 1)
            except ValueError:
                raise ValueError('Invalid module name %r set for import: %s' %
                                 (moduleName, traceback.format_exc()))
    else:
        _moduleName = moduleName
        
    if isinstance(objectName, basestring):
        objectName = [objectName]
    
    log.debug("Importing %r ..." % objectName) 
      
    module = __import__(_moduleName, globals(), locals(), [])
    components = _moduleName.split('.')
    try:
        for component in components[1:]:
            module = getattr(module, component)
    except AttributeError:
        raise AttributeError("Error importing %r: %s" %
                             (objectName, traceback.format_exc()))

    importedObject = module
    for i in objectName:
        importedObject = getattr(importedObject, i)

    # Check class inherits from a base class
    if objectType and not issubclass(importedObject, objectType):
        raise TypeError("Specified class %r must be derived from %r; got %r" %
                        (objectName, objectType, importedObject))
    
    log.info('Imported %r from module, %r', objectName, _moduleName)
    return importedObject


def callModuleObject(moduleName, objectName=None, moduleFilePath=None, 
                     objectType=None, objectArgs=None, objectProperties=None):
    '''
    Create and return an instance of the specified class or invoke callable
    @param moduleName: Name of module containing the class
    @type moduleName: str 
    @param objectName: Name of the class to instantiate.  May be None in 
    which case, the class name is parsed from the moduleName last element
    @type objectName: str
    @param moduleFilePath: Path to the module - if unset, assume module on 
    system path already
    @type moduleFilePath: str
    @param objectProperties: dict of properties to use when instantiating the 
    class
    @type objectProperties: dict
    @param objectType: expected type for the object to instantiate - to 
    enforce use of specific interfaces 
    @type objectType: object
    @return: object - instance of the class specified 
    '''

    # ensure that properties is a dict - NB, it may be passed in as a null
    # value which can override the default val
    if not objectProperties:
        objectProperties = {}

    if not objectArgs:
        objectArgs = ()
        
    # variable to store original state of the system path
    sysPathBak = None
    try:
        try:
            # Module file path may be None if the new module to be loaded
            # can be found in the existing system path            
            if moduleFilePath:
                if not os.path.exists(moduleFilePath):
                    raise IOError("Module file path '%s' doesn't exist" % 
                                  moduleFilePath)
                          
                # Temporarily extend system path ready for import
                sysPathBak = sys.path
                          
                sys.path.append(moduleFilePath)

            
            # Import module name specified in properties file
            importedObject = importModuleObject(moduleName, 
                                                objectName=objectName,
                                                objectType=objectType)
        finally:
            # revert back to original sys path, if necessary
            # NB, python requires the use of a try/finally OR a try/except 
            # block - not both combined
            if sysPathBak:
                sys.path = sysPathBak
                            
    except Exception, e:
        log.error('%r module import raised %r type exception: %r' % 
                  (moduleName, e.__class__, traceback.format_exc()))
        raise 

    # Instantiate class
    log.debug('Instantiating object "%s"' % importedObject.__name__)
    try:
        if objectArgs:
            obj = importedObject(*objectArgs, **objectProperties)
        else:
            obj = importedObject(**objectProperties)
            
        return obj

    except Exception, e:
        log.error("Instantiating module object, %r: %r" % 
                                                    (importedObject.__name__, 
                                                     traceback.format_exc()))
        raise
    

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
            