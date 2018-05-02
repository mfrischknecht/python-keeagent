#!/bin/env python
# -*- coding: utf-8 -*-

import os
import unittest

from SshAgent import SshAgentClient
from KeeAgent import SshEntry

from pykeepass import PyKeePass

os.chdir('./testdata/')

class TestSshEntries(unittest.TestCase):
    def setUp(self):
        self.kdb = PyKeePass('./keys.kdbx','1234')
        self.agent = SshAgentClient()

    def tearDown(self):
        self.agent.close()

    def test_embedded_rsa(self):
        entry = self.kdb.find_entries_by_path('embedded_keys/id_rsa')[0]
        ssh_entry = SshEntry(self.kdb,entry)
        private_key = ssh_entry.private_key

        self.agent.add_key(private_key)
        self.assertTrue(self.agent.is_key_active(private_key))

    def test_embedded_dsa(self):
        entry = self.kdb.find_entries_by_path('embedded_keys/id_dsa')[0]
        ssh_entry = SshEntry(self.kdb,entry)
        private_key = ssh_entry.private_key

        self.agent.add_key(private_key)
        self.assertTrue(self.agent.is_key_active(private_key))

    def test_embedded_ecdsa(self):
        entry = self.kdb.find_entries_by_path('embedded_keys/id_ecdsa')[0]
        ssh_entry = SshEntry(self.kdb,entry)
        private_key = ssh_entry.private_key

        self.agent.add_key(private_key)
        self.assertTrue(self.agent.is_key_active(private_key))

    def test_file_rsa(self):
        entry = self.kdb.find_entries_by_path('file_keys/id_rsa')[0]
        ssh_entry = SshEntry(self.kdb,entry)
        private_key = ssh_entry.private_key

        self.agent.add_key(private_key)
        self.assertTrue(self.agent.is_key_active(private_key))

    def test_file_dsa(self):
        entry = self.kdb.find_entries_by_path('file_keys/id_dsa')[0]
        ssh_entry = SshEntry(self.kdb,entry)
        private_key = ssh_entry.private_key

        self.agent.add_key(private_key)
        self.assertTrue(self.agent.is_key_active(private_key))

    def test_file_ecdsa(self):
        entry = self.kdb.find_entries_by_path('file_keys/id_ecdsa')[0]
        ssh_entry = SshEntry(self.kdb,entry)
        private_key = ssh_entry.private_key

        self.agent.add_key(private_key)
        self.assertTrue(self.agent.is_key_active(private_key))

    def test_passwordless_rsa(self):
        entry = self.kdb.find_entries_by_path('without_passphrase/id_rsa')[0]
        ssh_entry = SshEntry(self.kdb,entry)
        private_key = ssh_entry.private_key

        self.agent.add_key(private_key)
        self.assertTrue(self.agent.is_key_active(private_key))

    def test_passwordless_dsa(self):
        entry = self.kdb.find_entries_by_path('without_passphrase/id_dsa')[0]
        ssh_entry = SshEntry(self.kdb,entry)
        private_key = ssh_entry.private_key

        self.agent.add_key(private_key)
        self.assertTrue(self.agent.is_key_active(private_key))

    def test_passwordless_ecdsa(self):
        entry = self.kdb.find_entries_by_path('without_passphrase/id_ecdsa')[0]
        ssh_entry = SshEntry(self.kdb,entry)
        private_key = ssh_entry.private_key

        self.agent.add_key(private_key)
        self.assertTrue(self.agent.is_key_active(private_key))

if __name__ == '__main__':
    unittest.main()
