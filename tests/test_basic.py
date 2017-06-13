import unittest

import pkcs11


class BasicTests(unittest.TestCase):

    def setUp(self):
        self.lib = pkcs11.lib('python-pkcs11-provider.so')

    def test_get_slots(self):
        slots = self.lib.get_slots()
        print(slots)
