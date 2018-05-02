#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import traceback
import shutil
import stat
import tempfile
import zlib

from hashlib import sha256
from base64 import b64decode, b64encode
from binascii import a2b_base64
from collections import namedtuple
from lxml import objectify
from pykeepass import PyKeePass
from subprocess import Popen, PIPE
from time import sleep

#Non-standard imports:
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def get_binaries(kdb,entry):
    """Gets all binary entries for a given Keepass database entry.

    Example:

    >>> entry = KP_DB.find_entries_by_path('embedded_keys/id_rsa')[0]
    >>> list(get_binaries(KP_DB,entry))
    [('KeeAgent.settings', <...Binary object at ...>), ('id_rsa', <...Binary object at ...>)]
    """
    xml = objectify.fromstring(entry.dump_xml())
    binaries = list(xml.xpath('./Binary'))
    for binary in binaries:
        yield (binary.Key.text, Binary(kdb,binary))

class Binary:
    """A wrapper type representing a chunk of binary data saved to the Keepass database.

    Example:

    >>> entry = KP_DB.find_entries_by_path('embedded_keys/id_rsa')[0]
    >>> xml = objectify.fromstring(entry.dump_xml())
    >>> binaries = list(xml.xpath('./Binary'))
    >>> Binary(KP_DB,binaries[0])
    <...Binary object at ...>
    """
    def __init__(self,kdb,element):
        self.key = element.Key.text
        self.ref = element.Value.attrib['Ref']
        self._kdb = kdb

    _content = None
    @property
    def content(self):
        """Extracts, decodes and decompresses the binary data for this block.

        Returns the data as bytes.

        Example:

        >>> entry = KP_DB.find_entries_by_path('embedded_keys/id_rsa')[0]
        >>> binary = dict(get_binaries(KP_DB,entry))['KeeAgent.settings']
        >>> binary.content.decode('UTF-16')
        '<?xml version="1.0" encoding="UTF-16"?>\\n<EntrySettings...>...</EntrySettings>\\n'
        """
        if self._content is not None:
            return self._content

        binaries = self._kdb.kdb.obj_root.Meta.Binaries
        xpath = './Binary[@ID="{}"]'.format(self.ref)
        binary = binaries.xpath(xpath)[0]
        result = b64decode(binary.text)

        if (binary.attrib['Compressed']):
            result = zlib.decompress(result, 16+zlib.MAX_WBITS)

        self._content = result
        return self._content

class SshEntry:
    """A wrapper type for Keepass entries that extracts KeeAgent settings.

    Example:

    >>> entry = KP_DB.find_entries_by_path('embedded_keys/id_rsa')[0]
    >>> SshEntry(KP_DB,entry)
    <...SshEntry object at ...>
    """

    def __init__(self,kdb,entry):
        self.entry = entry
        self._xml = objectify.fromstring(entry.dump_xml())

        binaries = self._xml.xpath('./Binary')
        binaries = [Binary(kdb,b) for b in binaries]
        self.binaries = dict([(b.key, b) for b in binaries])

        settings = self.binaries['KeeAgent.settings']
        if not settings:
            raise KeyError('Entry has no KeeAgent settings')

    @property
    def passphrase(self):
        """Retrieves the SSH entry's passphrase (from the Keepass password field)

        >>> entry = KP_DB.find_entries_by_path('embedded_keys/id_rsa')[0]
        >>> ssh_entry = SshEntry(KP_DB,entry)
        >>> ssh_entry.passphrase.decode() == entry.password
        True
        """
        password = self.entry.password
        if password:
            return self.entry.password.encode('UTF-8')
        else:
            return None

    _settings = None
    @property
    def settings(self):
        """Parses the KeeAgent settings for the provided entry.

        >>> entry = KP_DB.find_entries_by_path('embedded_keys/id_rsa')[0]
        >>> ssh_entry = SshEntry(KP_DB,entry)
        >>> ssh_entry.settings
        <Element EntrySettings at ...>
        """
        if self._settings is not None:
            return self._settings

        settings = self.binaries['KeeAgent.settings'].content
        self._settings = objectify.fromstring(settings)
        return self._settings

    _serialized_private_key = None
    @property
    def serialized_private_key(self):
        """Returns the serialized variant of the stored private key for this entry.

        SSH keys can both be stored as attachments or references to keyfiles on disk.
        This property supports both and will automatically read the data from the right place.

        Returns the respective private key file as bytes.

        >>> entry = KP_DB.find_entries_by_path('embedded_keys/id_rsa')[0]
        >>> ssh_entry = SshEntry(KP_DB,entry)
        >>> ssh_entry.serialized_private_key
        b'-----BEGIN RSA PRIVATE KEY-----\\nProc-Type: 4,ENCRYPTED\\nDEK-Info: AES-128-CBC,...\\n-----END RSA PRIVATE KEY-----\\n'
        """
        if self._serialized_private_key is not None:
            return self._serialized_private_key

        location = self.settings.Location
        if location.AttachmentName:
            self._serialized_private_key = self.binaries[location.AttachmentName.text].content
            return self._serialized_private_key
        else:
            with open(location.FileName.text, 'rb') as file:
                self._serialized_private_key = file.read()
                return self._serialized_private_key

    _private_key_path = None
    @property
    def private_key_path(self):
        """Returns the path for the private key file associated with the SSH entry.

        If the private key file is stored as an attachment in the Keepass database,
        this property returns a URL with the pseudo-protocol `kdbx-attachment://`

        >>> entry = KP_DB.find_entries_by_path('embedded_keys/id_rsa')[0]
        >>> ssh_entry = SshEntry(KP_DB,entry)
        >>> ssh_entry.private_key_path
        'kdbx-attachment:///embedded_keys/id_rsa/id_rsa'
        """
        if self._private_key_path is not None:
            return self._private_key_path

        location = self.settings.Location
        if location.AttachmentName:
            self._private_key_path = 'kdbx-attachment:///{}/{}'.format(
                self.entry.path, location.AttachmentName.text)
            return self._private_key_path
        else:
            self._private_key_path = location.FileName.text
            return self._private_key_path

    _private_key = None
    @property
    def private_key(self):
        """Attempts to parse the private key file associated with the Keepass entry.

        Returns a PrivateKey tuple instance if successfull or `None` otherwise.

        Note: ed25519 private keys are currently not supported since there seems to be
              no easy python library solution for parsing/handling them.

        >>> entry = KP_DB.find_entries_by_path('embedded_keys/id_rsa')[0]
        >>> ssh_entry = SshEntry(KP_DB,entry)
        >>> ssh_entry.private_key
        <cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey object at ...>
        """
        if self._private_key is not None:
            return self._private_key[0]

        spk = self.serialized_private_key
        passphrase = self.passphrase

        try:
            self._private_key = [
                serialization.load_pem_private_key(
                    self.serialized_private_key,
                    backend=default_backend(),
                    password=self.passphrase)]

            return self._private_key[0]

        except:
            raise
            self._private_key = [None]
            return self._private_key[0]

def try_parse_ssh_entry(kdb,entry):
    """Attempts to wrap a Keepass entry with the `SshEntry` class.

    Returns the `SshEntry` instance if successful and `None` otherwise.
    """
    try:
        return SshEntry(kdb,entry)
    except:
        return None

def get_ssh_entries(kdb):
    """Iterates over all entries in a Keepass database and filters out the
    entries containing KeeAgent settings.

    >>> get_ssh_entries(KP_DB)
    [<...SshEntry object at ...>, ...]
    """
    entries = kdb.entries
    entries = [try_parse_ssh_entry(kdb,e) for e in entries]
    entries = [e for e in entries if e]
    return entries

if __name__ == '__main__':
    os.chdir('./testdata/')

    global KP_DB
    KP_DB = PyKeePass('./keys.kdbx','1234')

    import doctest
    doctest.testmod(optionflags=doctest.ELLIPSIS)
