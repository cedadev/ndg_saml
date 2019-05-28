'''ndg.saml.test.binding.soap.attribute_service_runner - run a test
Attribute Service based on Gunicorn WSGI application server
'''
__author__ = "Philip Kershaw"
__date__ = "5 Oct 2018"
__copyright__ = "Copyright 2019 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
from os import path
import sys

from paste.script.util.logging_config import fileConfig    
from paste.deploy import loadapp
  
import multiprocessing

import gunicorn.app.base
import gunicorn.arbiter


def number_of_workers():
    return (multiprocessing.cpu_count() * 2) + 1


class GunicornServerApp(gunicorn.app.base.BaseApplication):

    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        self.arbiter = None
        super().__init__()

    def load_config(self):
        config = dict([(key, value) for key, value in self.options.items()
                       if key in self.cfg.settings and value is not None])
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application
    
    def run(self):
        '''Extend in order to save arbiter reference'''
        try:
            self.arbiter = gunicorn.arbiter.Arbiter(self)
            self.arbiter.run()
        except RuntimeError as e:
            print("\nError: {}\n".format(e), file=sys.stderr)
            sys.stderr.flush()
            sys.exit(1)
            
    def kill_workers(self, sig):
        self.arbiter.kill_workers(sig)


if __name__ == '__main__':
    dir_name = path.dirname(__file__)
    options = {
        'bind': '%s:%s' % ('127.0.0.1', '5443'),
        'workers': number_of_workers(),
        'keyfile': path.join(dir_name, 'localhost.key'),
        'certfile': path.join(dir_name, 'localhost.crt')
    }
    cfgFilePath = path.join(dir_name, "attribute-interface.ini")
    fileConfig(cfgFilePath)
    app = loadapp('config:%s' % cfgFilePath)
    
    gunicorn_server_app = GunicornServerApp(app, options)
    app._app._app.gunicorn_server_app = gunicorn_server_app
    gunicorn_server_app.run()


