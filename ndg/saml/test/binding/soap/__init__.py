"""NDG SAML SOAP Binding unit test package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "21/08/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import os
import unittest
import socket
import warnings

try:
    import paste.fixture
    from paste.deploy import loadapp
    from ndg.soap.test import PasteDeployAppServer
    
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
                "<html><head/><body><h1>Stopping service</h1><body></html>".
                encode('utf-8'))
        else:
            response = (
                "<html><head/><body><h1>404 Not Found</h1><body></html>".
                encode('utf-8'))
        
        start_response(response,
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
        
    
class WithGunicornBaseTestCase(unittest.TestCase):
    """Base class for testing SAML SOAP Binding Query/Response interface
    using a Paste Deploy ini file and Gunicorn WSGI server to run a test
    service to test against
    """
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    CONFIG_FILENAME = None # Set in derived class
    SERVICE_PORTNUM = 5443
    SERVER_CERT_FILEPATH = os.path.join(THIS_DIR, 'localhost.crt')
    SERVER_PRIKEY_FILEPATH = os.path.join(THIS_DIR, 'localhost.key')
    
    def __init__(self, *arg, **kw):
        withSSL = kw.pop('withSSL', False)
        disableServiceStartup = kw.pop('disableServiceStartup', False)
        super().__init__(*arg, **kw)
        
        self.services = []
        self.disableServiceStartup = disableServiceStartup
        cfgFilePath = os.path.join(self.__class__.THIS_DIR, 
                                   self.__class__.CONFIG_FILENAME)
        
        self.addService(cfgFilePath=cfgFilePath,
                        withSSL=withSSL,
                        port=self.__class__.SERVICE_PORTNUM)
        
    def addService(self, *arg, **kw):
        """Utility for setting up threads to run Paste HTTP based services with
        unit tests
        
        :param arg: tuple contains ini file path setting for the service
        :type arg: tuple
        :param kw: keywords including "port" - port number to run the service 
        from
        :type kw: dict
        """
        if self.disableServiceStartup:
            return
        
        withSSL = kw.pop('withSSL', False)
        if withSSL:
            from OpenSSL import SSL
            
            certFilePath = self.__class__.SERVER_CERT_FILEPATH
            priKeyFilePath = self.__class__.SERVER_PRIKEY_FILEPATH
            
            kw['ssl_context'] = SSL.Context(SSL.TLSv1_2_METHOD)
        
            kw['ssl_context'].use_privatekey_file(priKeyFilePath)
            kw['ssl_context'].use_certificate_file(certFilePath)
        
        try:
            self.services.append(PasteDeployAppServer(*arg, **kw))
            self.services[-1].startThread()
            
        except socket.error:
            pass

    def __del__(self):
        """Stop any services started with the addService method and clean up
        the CA directory following the trust roots call
        """

        if hasattr(self, 'services'):
            for service in self.services:
                service.terminateThread()

