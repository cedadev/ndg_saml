'''ndg.saml.test.test_utils - test SAML Utilities module
'''
__author__ = "Philip Kershaw"
__date__ = "4 Oct 2018"
__copyright__ = "Copyright 2019 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level package directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
import unittest
import pickle

from ndg.saml.utils import TypedList


class SamlUtilsTestCase(unittest.TestCase): 
    '''Test SAML utilities module
    '''

    def test01_pickle_typedlist(self):
        int_list = TypedList(int)
        int_list.append(9)
        int_list.append(10)
        
        int_list_jar = pickle.dumps(int_list)
        int_list_restore = pickle.loads(int_list_jar)
        
        self.assertEqual(len(int_list_restore), 2, 
                         'Expecting 2 elements in restored list')
        
        
if __name__ == "__main__":
    unittest.main()