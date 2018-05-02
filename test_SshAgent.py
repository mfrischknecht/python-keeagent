#!/bin/env python
# -*- coding: utf-8 -*-

import unittest

from SshAgent import SshAgentClient, ConfirmationConstraint, LifetimeConstraint

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

class TestSshAgent(unittest.TestCase):
    password = b'12345'
    key_files = {
        'RSA'  : './testdata/embedded_keys/id_rsa',
        'DSA'  : './testdata/embedded_keys/id_dsa',
        'ECDSA': './testdata/embedded_keys/id_ecdsa',
        #'ED25519': './embedded_keys/id_ed25519', #Not yet supported by pyca/cryptography
    }

    def setUp(self):
        self.agent = SshAgentClient()
        self.keys = dict(self._load_key(f) for f in self.key_files.values())

    def tearDown(self):
        self.agent.close()

    def _load_key(self,key_file):
        with open(key_file,'rb') as f:
            key = serialization.load_pem_private_key(
                    f.read(),
                    backend=default_backend(),
                    password=self.password)

            return (key_file, key)

    def _test_key(self,key):
        self.agent.add_key(key)
        self.assertTrue(self.agent.is_key_active(key))

        self.agent.remove_key(key)
        self.assertFalse(self.agent.is_key_active(key))

        confirm = ConfirmationConstraint()
        lifetime = LifetimeConstraint(100)

        self.agent.add_key(key, constraints=[confirm])
        self.assertTrue(self.agent.is_key_active(key))
        self.agent.remove_key(key.public_key())

        self.agent.add_key(key, constraints=[lifetime])
        self.assertTrue(self.agent.is_key_active(key))
        self.agent.remove_key(key.public_key())

        self.agent.add_key(key, constraints=[confirm,lifetime])
        self.assertTrue(self.agent.is_key_active(key))
        self.agent.remove_key(key.public_key())

    def test_rsa(self):
        key = self.keys[self.key_files['RSA']]
        self._test_key(key)

    def test_dsa(self):
        key = self.keys[self.key_files['DSA']]
        self._test_key(key)

    def test_ecdsa(self):
        key = self.keys[self.key_files['ECDSA']]
        self._test_key(key)

    def test_clear(self):
        for key in self.keys.values():
            self.agent.add_key(key)

        for key in self.keys.values():
            self.assertTrue(self.agent.is_key_active(key))

        self.agent.clear_all_keys()

        active_keys = list(self.agent.query_active_keys())
        self.assertFalse(any(active_keys))

if __name__ == '__main__':
    unittest.main()
