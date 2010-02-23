#!/usr/bin/env python
"""SAML Package 

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "10/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id:$'

# Bootstrap setuptools if necessary.
from ez_setup import use_setuptools
use_setuptools()
from setuptools import setup, find_packages
import os
   
_longDescription = """\
SAML 2.0 implementation for use with the NERC DataGrid Attribute and 
Authorisation Query interfaces.  The implementation is based on the Java 
OpenSAML libraries.  An implementation is provided using ElementTree although it
is also possible to add plugins for other Python XML parsers.

It is not a complete implementation of SAML 2.0.  Only those components required
for the NERC DataGrid have been provided (Attribute and AuthZ Decision Query/
Response).  Where possible, stubs have been provided for other classes.
"""

setup(
    name =           		'ndg_security_saml',
    version =        		'0.3',
    description =    		('SAML 2.0 implementation for the NERC DataGrid '
                             'based on the Java OpenSAML library'),
    long_description =		(),
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'http://proj.badc.rl.ac.uk/ndg/wiki/Security',
    license =               'BSD - See LICENCE file for details',
    packages =			    find_packages(),
    namespace_packages =	[],
    include_package_data =  True,
    zip_safe =              False
)
