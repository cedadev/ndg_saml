"""Utilities package for NDG Security SAML implementation

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "02/04/09"
__copyright__ = ""
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'

class TypedList(list):
    """Extend list type to enabled only items of a given type.  Supports
    any type where the array type in the Standard Library is restricted to 
    only limited set of primitive types
    """
    
    def __init__(self, elementType, *arg, **kw):
        """
        @type elementType: type/tuple
        @param elementType: object type or types which the list is allowed to
        contain.  If more than one type, pass as a tuple
        """
        self.__elementType = elementType
        super(TypedList, self).__init__(*arg, **kw)
    
    def _getElementType(self):
        return self.__elementType
    
    elementType = property(fget=_getElementType, 
                           doc="The allowed type or types for list elements")
     
    def extend(self, iter):
        for i in iter:
            if not isinstance(i, self.__elementType):
                raise TypeError("List items must be of type %s" % 
                                (self.__elementType,))
                
        return super(TypedList, self).extend(iter)
        
    def __iadd__(self, iter):
        for i in iter:
            if not isinstance(i, self.__elementType):
                raise TypeError("List items must be of type %s" % 
                                (self.__elementType,))
                    
        return super(TypedList, self).__iadd__(iter)
         
    def append(self, item):
        if not isinstance(item, self.__elementType):
                raise TypeError("List items must be of type %s" % 
                                (self.__elementType,))
    
        return super(TypedList, self).append(item)
