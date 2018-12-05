"""SOAP Server helper module for unit test

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "27/07/09"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "http://www.apache.org/licenses/LICENSE-2.0"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
import sys
from ndg.soap.test.test_soap import SOAPBindingMiddleware
from paste.httpserver import serve

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
            print("\nError: %s\n" % e, file=sys.stderr)
            sys.stderr.flush()
            sys.exit(1)
            
    def kill_workers(self, sig):
        self.arbiter.kill_workers(sig)


if __name__ == "__main__":
    app = SOAPBindingMiddleware()
    serve(app, host='0.0.0.0', port=10080)
    options = {
        'bind': '%s:%s' % ('127.0.0.1', '10080'),
        'workers': number_of_workers(),
    }
    gunicorn_server_app = GunicornServerApp(app, options)
    app._app._app.gunicorn_server_app = gunicorn_server_app
    gunicorn_server_app.run()
