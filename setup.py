#!/usr/bin/env python
"""SAML 2.0 Package

NERC DataGrid Project

This implementation is adapted from the Java OpenSAML implementation.
"""
__author__ = "P J Kershaw"
__date__ = "10/08/09"
__copyright__ = "Copyright 2019 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"

# Bootstrap setuptools if necessary.
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages
   
with open('README.md') as f:
    _long_description = f.read()
    
setup(
    name =                  'ndg_saml',
    version =        		'0.9.0',
    description =    		('SAML 2.0 implementation for the NERC DataGrid '
                                'based on the Java OpenSAML library'),
    long_description =		_long_description,
    long_description_content_type='text/markdown',
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'https://github.com/cedadev/ndg_saml',
    license =               'BSD - See ndg/saml/LICENCE file for details',
    packages =              find_packages(),
    package_data =          {
        'ndg.saml': [
            'LICENSE',
            'test/binding/soap/*.ini',
            'test/binding/soap/localhost.*',
            'test/binding/soap/ca/*.0'
            ],
        'ndg.soap': [
            'LICENSE',
            ],
    },
    extras_require =        {
        # These additional packages are needed if you wish to use the SOAP 
        # binding, Nb. M2Crypto can be used in place of ndg-httpsclient if
        # required. ndg-httpsclient provides a urllib2 interface to PyOpenSSL
        'soap_binding':  ["ndg-httpsclient", 
                          "Paste>=2.0.3", 
                          "PasteDeploy>=2.0.1", 
                          "PasteScript>=2.0.2"],
        'test_http_server': ['waitress', 'gunicorn'],
        # Required for the SAML profile to XACML - enables richer functionality
        # for expressing authorisation queries and decisions.
        'xacml_profile': ['ndg_xacml'],
    },
    entry_points =          {
    'console_scripts': [
        'ndg_saml_client = ndg.saml.utils.command_line_client:'
        'SamlSoapCommandLineClient.main',
        ],
    },
    classifiers =           [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Distributed Computing',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    zip_safe=False
)
