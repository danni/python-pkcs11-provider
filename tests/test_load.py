import unittest

import pkcs11


class LoadTests(unittest.TestCase):

    def test_load(self):
        lib = pkcs11.lib('python-pkcs11-provider.so')
