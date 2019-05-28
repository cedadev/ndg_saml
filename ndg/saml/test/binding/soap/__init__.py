"""NDG SAML SOAP Binding unit test package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "21/08/09"
__copyright__ = "Copyright 2019 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import os
import unittest
import socket
import warnings

try:
    import paste.fixture
    from paste.deploy import loadapp
    
    paste_installed = True
except ImportError as import_exc:
    warnings.warn("Checking Paste package dependencies: {}".format(
                  import_exc))
    paste_installed = False
    

class TestApp:
    """Dummy application to terminate middleware stack containing SAML service
    
    Use for testing ONLY.  stop-service/ path provides a crude mechanism
    to destroy the app at the end of a test run
    """
    def __init__(self, global_conf, **app_conf):
        pass
    
    def __call__(self, environ, start_response):
        
        if environ.get('PATH_INFO') == '/stop-service/':
            # Self-destruct application!
            import signal
            self.gunicorn_server_app.kill_workers(signal.SIGKILL)
      
            response = (
                "<html><head/><body><h1>Stopping service</h1></body></html>".
                encode('utf-8'))
            code = "200 OK".encode('utf-8')
        else:
            response = (
                "<html><head/><body><h1>404 Not Found</h1></body></html>".
                encode('utf-8'))
            code = "404 Not Found"#.encode('utf-8')
        
        start_response(code,
                       [('Content-length', str(len(response))),
                        ('Content-type', 'text/html')])
                            
        return [response]


class WithPasteFixtureBaseTestCase(unittest.TestCase):
    """Base class for testing SAML SOAP Binding Query/Response interface
    using a Paste Deploy ini file and Paste Fixture
    """
    HERE_DIR = os.path.dirname(os.path.abspath(__file__))
    CONFIG_FILENAME = None # Set in derived class
    
    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        
        if not paste_installed:
            warnings.warn('Disabling WithPasteFixtureBaseTestCase, '
                          'Paste.Deploy package is not installed')
            self.app = None
            return
        
        wsgiapp = loadapp('config:%s' % self.__class__.CONFIG_FILENAME, 
                          relative_to=self.__class__.HERE_DIR)
        
        self.app = paste.fixture.TestApp(wsgiapp)     
        