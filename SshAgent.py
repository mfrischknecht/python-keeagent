#!/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import struct
import math
import socket

from base64 import b64decode, b64encode
from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

if sys.version_info[0] == 3:
    from types import SimpleNamespace

else:
    class SimpleNamespace (object):
        def __init__ (self, **kwargs):
            self.__dict__.update(kwargs)
        def __repr__ (self):
            keys = sorted(self.__dict__)
            items = ("{}={!r}".format(k, self.__dict__[k]) for k in keys)
            return "{}({})".format(type(self).__name__, ", ".join(items))
        def __eq__ (self, other):
            return self.__dict__ == other.__dict__


#Implementation of the SSH agent protocol
#cf. Protocol Specification:               https://tools.ietf.org/id/draft-miller-ssh-agent-00.html
#cf. Further Reading (serialization etc.): https://www.ietf.org/rfc/rfc4251.txt

class ReadMessage:
    """A message type implementing the deserialization of primitives used by the SSH agent protocol.

    >>> ReadMessage(b'\\x00\\x00\\x00\\x00')
    <__main__.ReadMessage object at ...>
    """

    def __init__(self,bytes):
        self._original_data = bytearray(bytes)
        self.data = self._original_data

    @property
    def original(self):
        """Retains the original message even after deserialization operations have been performed.

        >>> message = ReadMessage(b'\\x00\\x00\\x00\\x00')
        >>> message.read_uint32()
        0

        >>> len(message.data)
        0

        >>> message.original.data
        bytearray(b'\\x00\\x00\\x00\\x00')
        """
        return ReadMessage(self._original_data)

    def read_uint8(self):
        """Reads a single byte from the underlying message and moves on its position.

        >>> message = ReadMessage(b'\\xC0\\xDE')
        >>> message.read_uint8()
        192

        >>> message.data
        bytearray(b'\\xde')
        """
        bytes = self.data[:1]
        value = struct.unpack('!B',bytes)[0]
        self.data = self.data[1:]
        return value

    def read_uint32(self):
        """Reads an unsigned 32-bit integer from the underlying message and moves on its position.

        >>> message = ReadMessage(b'\\xCA\\xFE\\xC0\\01\\xDE\\xCA\\xFB\\xAD')
        >>> message.read_uint32()
        3405692929

        >>> message.data
        bytearray(b'\\xde\\xca\\xfb\\xad')
        """
        bytes = self.data[:4]
        value = struct.unpack('!I',bytes)[0]
        self.data = self.data[4:]
        return value

    def read_mpint(self):
        """Reads a multiple precision integer value from the underlying message and moves on its position.

        >>> message = ReadMessage(b"\\x00\\x00\\x00\\x81\\x00\\xe9Y\\xc9\\xba\\xf0_\\x83\\x99j\\xdes\\xd6\\x1br|\\x04\\xdeen\\xc6\\xb6s\\xb4\\xff~\\x83:f\\xfb\\x18\\xda\\xfbP\\xbb\\xae*\\x99\\x04\\xb4\\xe4\\x04\\xb8\\xb9\\xba\\x1d%\\xf3\\xda\\x0e\\xce\\xf9\\x18f^\\xd3\\xab\\xdd!-\\xe0\\xb4\\xc6}\\x04\\x14\\xcdR\\xa0\\xda&\\x9d\\xbb\\xb8)H]`\\xa0\\xa9\\x1d\\xe0\\x8e\\x7f\\xd0\\xd7\\xeck\\x1a\\x91\\x16\\x0c-j\\x08/\\xd7\\x03W\\xf5:\\x12\\xa7\\xf2\\xe0\\xaa\\xf5\\xae\\x8a\\xac\\x8e\\xcc\\xd2\\'\\xb9\\xd6\\xb1\\x89\\x05\\x99\\xc5h\\xf1\\\\\\xb7\\x10g_c\\xDE\\xAD\\xBE\\xEF")
        >>> message.read_mpint()
        163864458305545277937930594972303634760701478468816201673836270580526630692126147047277874038509393784810055183452973707038467393052665608683044105066567593918084927743573553959942584638852709496561186789241587697553567373649846343660448066502958985042292514052243142823000582426130090434895154402951233494883

        >>> message.data
        bytearray(b'\\xde\\xad\\xbe\\xef')
        """
        data = self.read_binary()
        if len(data) == 0: return 0

        #Note: We do the math MSB first, so we don't have to flip the number again
        number = 0
        for byte in data:
            number <<= 8
            number |= byte

        if (data[0] & 0x80) != 0: #Signed bit is set
            #Interpret the number as a two's complement
            number = number - (1 << (8*num_bytes))

        return number

    def read_binary(self):
        """Reads a string of bytes from the underlying message and moves on its position.

        >>> message = ReadMessage(b"\\x00\\x00\\x00\\x04\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08")
        >>> message.read_binary()
        bytearray(b'\\x01\\x02\\x03\\x04')

        >>> message.data
        bytearray(b'\\x05\\x06\\x07\\x08')
        """
        length = self.read_uint32()
        bytes = self.data[:length]
        self.data = self.data[length:]
        return bytes

    def read_string(self):
        """
        >>> message = ReadMessage(b"\\x00\\x00\\x00\\x76La parfaite valeur est de faire sans t\\xc3\\xa9moin ce qu'on serait capable de faire devant tout le monde. --La Rochefoucauld\\x00")
        >>> message.read_string()
        "La parfaite valeur est de faire sans témoin ce qu'on serait capable de faire devant tout le monde. --La Rochefoucauld"

        >>> message.data
        bytearray(b'\\x00')
        """
        data = self.read_binary()
        return data.decode('UTF-8')

class WriteMessage:
    """A message type implementing the serialization of primitives used by the SSH agent protocol.

    >>> message = WriteMessage()
    >>> message
    <__main__.WriteMessage object at ...>

    >>> message.data
    bytearray(b'')

    >>> message = WriteMessage(b'\\x00\\x00\\x00\\x00')
    >>> message.data
    bytearray(b'\\x00\\x00\\x00\\x00')
    """
    def __init__(self,bytes=None):
        self.data = bytearray(bytes or b'')

    def write_uint8(self,value):
        """Appends a single byte value to the underlying buffer.

        >>> message = WriteMessage()
        >>> message.write_uint8(0xFF)
        >>> message.data
        bytearray(b'\\xff')

        >>> message.write_uint8(0x42)
        >>> message.data
        bytearray(b'\\xffB')
        """
        packed = struct.pack('!B',value)
        self.data.extend(packed)

    def write_uint32(self,value):
        """Appends a 32 bit unsigned integer value to the underlying buffer.

        >>> message = WriteMessage()
        >>> message.write_uint32(0)
        >>> message.data
        bytearray(b'\\x00\\x00\\x00\\x00')

        >>> message.write_uint32(0xFFFFFFFF)
        >>> message.data
        bytearray(b'\\x00\\x00\\x00\\x00\\xff\\xff\\xff\\xff')
        """
        packed = struct.pack('!I',value)
        self.data.extend(packed)

    def write_mpint(self,value):
        """Appends a multiple precision integer value to the underlying buffer.

        >>> message = WriteMessage()
        >>> message.write_mpint(1203124320530329532049320955328509250258302952)
        >>> message.data
        bytearray(b'\\x00\\x00\\x00\\x135\\xf30\\x9a\\xf4\\xfd\\xa84~\\\\\\xcc\\xce\\xec\\xfb\\xc2\\x1a\\x1fw\\xe8')

        >>> message.write_mpint(1638644583055452779379305949723036347607014784688162016738362705805266306921261470472778740)
        >>> message.data
        bytearray(b"\\x00\\x00\\x00\\x135\\xf30\\x9a\\xf4\\xfd\\xa84~\\\\\\xcc\\xce\\xec\\xfb\\xc2\\x1a\\x1fw\\xe8\\x00\\x00\\x00&\\x0c\\xde\\xed\\xbcj\\'Y)l\\xe4\\xf5\\x08\\r\\x95\\xbcRX\\x90_\\x08\\x14\\x81\\xa6T\\xf4}\\xae\\x97\\x19\\x1d\\x96\\r\\xc9\\xcd9\\x90\\xb3\\xf4")
        """
        if value == 0:
            self.write_binary(b'')
            return

        num_bits = value.bit_length()+1 #Accommodate the sign bit
        num_bytes = int(math.ceil(num_bits/8.0))
        buffer = bytearray(num_bytes)

        tmp = value
        for i in range(num_bytes):
            byte = tmp & 0xFF
            tmp >>= 8
            struct.pack_into('!B',buffer,i,byte)

        buffer.reverse() #Network order: MSB first

        # #If the last byte is not necessary because the
        # #most significant bit is 0 anyway, remove it
        # if value >= 0 and\
        #    len(buffer) > 1 and\
        #    buffer[-2] & 0x80 == 0:
        #    buffer.pop()

        self.write_binary(buffer)

    def write_binary(self,value):
        """Appends a string of bytes integer value to the underlying buffer.

        >>> message = WriteMessage()
        >>> message.write_binary(b'1234567890')
        >>> message.data
        bytearray(b'\\x00\\x00\\x00\\n1234567890')

        >>> message.write_binary(b'abcdefghijklmnopqrstuvwxyz')
        >>> message.data
        bytearray(b'\\x00\\x00\\x00\\n1234567890\\x00\\x00\\x00\\x1aabcdefghijklmnopqrstuvwxyz')
        """
        self.write_uint32(len(value))
        self.data.extend(value)

    def write_string(self,value):
        """Appends a string of bytes integer value to the underlying buffer.

        >>> message = WriteMessage()
        >>> message.write_string(u'De Paapscht hät z Schpiez s Schpäckschpickpschteck z schpaat pschtellt.')
        >>> message.data
        bytearray(b'\\x00\\x00\\x00IDe Paapscht h\\xc3\\xa4t z Schpiez s Schp\\xc3\\xa4ckschpickpschteck z schpaat pschtellt.')


        >>> message.write_string(u'Gang gäng gredi gäge Gümlige go gugge, g’ob Göde Gödels Geranium gäng no gäge Gümlige gugge.')
        >>> message.data
        bytearray(b'\\x00\\x00\\x00IDe Paapscht h\\xc3\\xa4t z Schpiez s Schp\\xc3\\xa4ckschpickpschteck z schpaat pschtellt.\\x00\\x00\\x00fGang g\\xc3\\xa4ng gredi g\\xc3\\xa4ge G\\xc3\\xbcmlige go gugge, g\\xe2\\x80\\x99ob G\\xc3\\xb6de G\\xc3\\xb6dels Geranium g\\xc3\\xa4ng no g\\xc3\\xa4ge G\\xc3\\xbcmlige gugge.')
        """
        data = value.encode('UTF-8')
        self.write_binary(data)

class MessageConnection:
    """A basic connection class that allows for an exchange of messages with the SSH Agent daemon."""

    #Don't read messages larger than 4KiB
    MAX_MESSAGE_LENGTH = 4 << 10

    def __init__(self,socket):
        self.socket = socket

    def close(self):
        """Closes the underlying socket of the connection"""
        self.socket.close()

    def receive_message(self):
        """Receive a message from the SSH Agent daemon.

        This method raises a `ValueError` if the SSH Agent daemon transmitted a message that
        is longer than `MAX_MESSAGE_LENGTH`.
        """
        num_bytes = ReadMessage(self.socket.recv(4)).read_uint32()

        if num_bytes > self.MAX_MESSAGE_LENGTH:
            raise ValueError('Message from agent is too long ({} bytes)'.format(num_bytes))

        return self.socket.recv(num_bytes)

    def send_message(self,data):
        """Send a message to the SSH Agent daemon."""
        num_bytes = len(data)
        message = WriteMessage()
        message.write_uint32(num_bytes)
        message.data.extend(data)
        self.socket.sendall(message.data)

# A collection of constants used by the SSH Agent protocol
#cf. https://tools.ietf.org/id/draft-miller-ssh-agent-00.html, Sections 5.1-5.3

constants = SimpleNamespace(**{
    'request': SimpleNamespace(**{
        'SSH_AGENTC_REQUEST_IDENTITIES':            11,
        'SSH_AGENTC_SIGN_REQUEST':                  13,
        'SSH_AGENTC_ADD_IDENTITY':                  17,
        'SSH_AGENTC_REMOVE_IDENTITY':               18,
        'SSH_AGENTC_REMOVE_ALL_IDENTITIES':         19,
        'SSH_AGENTC_ADD_ID_CONSTRAINED':            25,
        'SSH_AGENTC_ADD_SMARTCARD_KEY':             20,
        'SSH_AGENTC_REMOVE_SMARTCARD_KEY':          21,
        'SSH_AGENTC_LOCK':                          22,
        'SSH_AGENTC_UNLOCK':                        23,
        'SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED': 26,
        'SSH_AGENTC_EXTENSION':                     27,
    }),

    'response': SimpleNamespace(**{
        'SSH_AGENT_FAILURE':                         5,
        'SSH_AGENT_SUCCESS':                         6,
        'SSH_AGENT_EXTENSION_FAILURE':              28,
        'SSH_AGENT_IDENTITIES_ANSWER':              12,
        'SSH_AGENT_SIGN_RESPONSE':                  14,
    }),

    'constraint': SimpleNamespace(**{
        'SSH_AGENT_CONSTRAIN_LIFETIME':              1,
        'SSH_AGENT_CONSTRAIN_CONFIRM':               2,
        'SSH_AGENT_CONSTRAIN_EXTENSION':             3,
    }),

    'signature': SimpleNamespace(**{
        'SSH_AGENT_RSA_SHA2_256':                    2,
        'SSH_AGENT_RSA_SHA2_512':                    4,
    }),
})


class SshAgentOperationFailed(Exception):
    """An error type that is raised if the SSH Agent reports that a
    requested operation could not be performed correctly.
    """
    pass

class SshAgentClient:
    """A class that can be used to send commands to the SSH Agent daemon.

    Usage examples:

    >>> key = None
    >>> with open('./embedded_keys/id_rsa','rb') as file:
    ...     key = serialization.load_pem_private_key(
    ...     file.read(), backend=default_backend(), password=b'12345')
    >>> client = SshAgentClient()

    >>> client.add_key(key,comment='<your comment here>')
    >>> client.is_key_active(key)
    True

    >>> list(client.query_active_keys())
    [(bytearray(b'...'), '<your comment here>')]

    >>> client.remove_key(key)
    >>> client.is_key_active(key)
    False

    >>> client.clear_all_keys()
    >>> list(client.query_active_keys())
    []
    """

    def __init__(self,socket_=None):
        """Initializes the SshAgentClient instance. If a socket is provided, it will be used
        for the communication with the SSH Agent daemon; otherwise the class will initialize
        a socket on the basis of the $SSH_AUTH_SOCK environment variable by itself.
        """
        if socket_:
            self.socket = socket_
        else:
            socket_path = None
            try: socket_path = os.environ['SSH_AUTH_SOCK']
            except: raise KeyError('Missing environment variable SSH_AUTH_SOCK')

            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(socket_path)
            self.socket = sock

        self.connection = MessageConnection(self.socket)

    def close(self):
        """Closes the underlying connection of the client"""
        self.connection.close()

    def __enter__(self):
        """Allows SshAgentClient instances to be used using the `with` statement"""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Allows SshAgentClient instances to be used using the `with` statement"""
        self.close()
        return False

    def _assert_success(self,code):
        """Makes sure that the response code from the SSH Agent signifies success and raises an error otherwise."""
        if code == constants.response.SSH_AGENT_FAILURE:
            raise SshAgentOperationFailed()
        elif code != constants.response.SSH_AGENT_SUCCESS:
            raise ValueError('The SSH agent responded using an unknown result code ({})'.format(code))

    def _await_operation_result(self):
        """Receives a response message from the SSH agent and checks the return code for errors."""
        response = ReadMessage(self.connection.receive_message())
        result = response.read_uint8()
        self._assert_success(result)

    def add_key(self,private_key,constraints=None,comment=None):
        """Adds an unlocked private key to the running SSH Agent session.

        The key can be tied to constraints; e.g. the SSH Agent can be told to always
        require a confirmation from the user if a key is used (cf. `ConfirmationConstraint`)
        or that a key should expire after a certain amount of seconds (cf. `LifetimeConstraint`).
        """
        message = self._build_add_key_message(private_key,constraints,comment)
        self.connection.send_message(message)
        self._await_operation_result()

    def remove_key(self,key):
        """Removes an active key from the running SSH Agent session.
        The provided key can either be an unlocked private key or the according public key.
        """
        public_key = key
        try: public_key = key.public_key()
        except: pass

        serialized = public_key.public_bytes(
            encoding = serialization.Encoding    .OpenSSH,
            format   = serialization.PublicFormat.OpenSSH)

        blob = serialized.split(None,2)[1]
        data = b64decode(blob)

        message = WriteMessage()
        message.write_uint8(constants.request.SSH_AGENTC_REMOVE_IDENTITY)
        message.write_binary(data)
        self.connection.send_message(message.data)
        self._await_operation_result()

    def clear_all_keys(self):
        """Removes all active keys from the running SSH Agent session."""
        message = WriteMessage()
        message.write_uint8(constants.request.SSH_AGENTC_REMOVE_ALL_IDENTITIES)
        self.connection.send_message(message.data)
        self._await_operation_result()

    def query_active_keys(self):
        """Queries the SSH Agent for the public keys of all active keys in the running session.
        Returns a sequence of tuples containing the public key and the respective comment for
        each active key.
        """
        message = WriteMessage()
        message.write_uint8(constants.request.SSH_AGENTC_REQUEST_IDENTITIES)
        self.connection.send_message(message.data)

        response = ReadMessage(self.connection.receive_message())
        code = response.read_uint8()
        if code != constants.response.SSH_AGENT_IDENTITIES_ANSWER:
            raise ValueError('The SSH agent responded using an invalid result code ({})'.format(code))

        num_keys = response.read_uint32()
        for i in range(num_keys):
            data = response.read_binary()
            comment = response.read_string()
            yield data, comment

    def is_key_active(self,key):
        """Checks whether the provided key is currently active in the running SSH Agent session.

        The provided key can either be an unlocked private key or the respective public key.
        """
        try: key = key.public_key()
        except: pass

        serialized = key.public_bytes(
            encoding = serialization.Encoding    .OpenSSH,
            format   = serialization.PublicFormat.OpenSSH)

        blob = b64decode(serialized.split(None,2)[1])
        active_keys = list(self.query_active_keys())

        for active_key in active_keys:
            if active_key[0] == blob:
                return True

        return False

    def _build_add_key_message(self,private_key,constraints=None,comment=None):
        """Builds a message signaling the SSH Agent to add a new key to the running session.

        Note: ed25519 keys are currently not supported.
        """
        comment = comment or ''

        message = WriteMessage()
        if not constraints:
            message.write_uint8(constants.request.SSH_AGENTC_ADD_IDENTITY)
        else:
            message.write_uint8(constants.request.SSH_AGENTC_ADD_ID_CONSTRAINED)

        if isinstance(private_key,rsa.RSAPrivateKey):
            key_data = self._rsa_key(private_key)
            message.data.extend(key_data)

        elif isinstance(private_key,dsa.DSAPrivateKey):
            key_data = self._dsa_key(private_key)
            message.data.extend(key_data)

        elif isinstance(private_key,ec.EllipticCurvePrivateKey):
            key_data = self._ecdsa_key(private_key)
            message.data.extend(key_data)

        #ED25519 Curves are not supported yet. cf. https://github.com/pyca/cryptography/pull/4114

        else:
            module     = private_key.__class__.__module__
            class_name = private_key.__class__.__name__
            raise NotImplementedError('Unknown key type {}.{}'.format(module,class_name))

        message.write_string(comment)

        if constraints:
            constraints = list(constraints)
            # message.write_uint32(len(constraints))
            for constraint in constraints:
                message.data.extend(constraint.serialize())

        return message.data


    def _rsa_key(self,private_key):
        """Serializes a RSA private key"""
        numbers = private_key.private_numbers()
        content = WriteMessage()
        content.write_string('ssh-rsa')
        content.write_mpint(numbers.public_numbers.n)
        content.write_mpint(numbers.public_numbers.e)
        content.write_mpint(numbers.d)
        content.write_mpint(numbers.iqmp)
        content.write_mpint(numbers.p)
        content.write_mpint(numbers.q)
        return content.data

    def _dsa_key(self,private_key):
        """Serializes a DSA private key"""
        numbers = private_key.private_numbers()
        content = WriteMessage()
        content.write_string('ssh-dss')
        content.write_mpint(numbers.public_numbers.parameter_numbers.p)
        content.write_mpint(numbers.public_numbers.parameter_numbers.q)
        content.write_mpint(numbers.public_numbers.parameter_numbers.g)
        content.write_mpint(numbers.public_numbers.y)
        content.write_mpint(numbers.x)
        return content.data

    #cf. https://tools.ietf.org/html/rfc5656#section-10
    #    Sections 10.1 and 10.2
    _ecdsa_nists = {
        # Required (10.1)
        #  SEC          NIST            OID
        'secp256r1': 'nistp256', #1.2.840.10045.3.1.7
        'secp384r1': 'nistp384', #1.3.132.0.34
        'secp521r1': 'nistp521', #1.3.132.0.35

        # Recommended (10.2)
        #  SEC          NIST            OID
        'sect163k1': 'nistk163', #1.3.132.0.1
        'secp192r1': 'nistp192', #1.2.840.10045.3.1.1
        'secp224r1': 'nistp224', #1.3.132.0.33
        'sect233k1': 'nistk233', #1.3.132.0.26
        'sect233r1': 'nistb233', #1.3.132.0.27
        'sect283k1': 'nistk283', #1.3.132.0.16
        'sect409k1': 'nistk409', #1.3.132.0.36
        'sect409r1': 'nistb409', #1.3.132.0.37
        'sect571k1': 'nistt571', #1.3.132.0.38
    }

    def _ecdsa_key(self,private_key):
        """Serializes a ECDSA (ecc) private key"""
        numbers = private_key.private_numbers()
        content = WriteMessage()

        public_key = private_key.public_key()
        serialized = public_key.public_bytes(
            encoding = serialization.Encoding    .OpenSSH,
            format   = serialization.PublicFormat.OpenSSH)


        # The SSH agent format somehow combines the elliptic curve's
        # `x` and `y` values (in `numbers.public_numbers`) into a single
        # `Q` value. I couldn't figure the specifics out exactly, but
        # the format is used exactly the same way int the OpenSSH
        # public key format, so we'll just reuse that one instead.

        pk_data = b64decode(serialized.split(None,2)[1])
        content.data.extend(pk_data)

        # nist = self._ecdsa_nists[private_key.curve.name]
        # content.write_string('ecdsa-sha2-{}'.format(nist))
        # content.write_string(nist)
        #
        # buffer = bytearray()
        # buffer.extend(b'0x04')
        #
        # x = numbers.public_numbers.x
        # y = numbers.public_numbers.y
        # for number in [x,y]:
        #     tmp = WriteMessage()
        #     tmp.write_mpint(number)
        #     buffer.extend(tmp.data[4:])

        content.write_mpint(numbers.private_value)
        return content.data

class LifetimeConstraint:
    """A constraint type that signals the SSH Agent to limit a key's lifetime"""

    def __init__(self,seconds):
        self.seconds = seconds

    def serialize(self):
        serialized = WriteMessage()
        serialized.write_uint8(constants.constraint.SSH_AGENT_CONSTRAIN_LIFETIME)
        serialized.write_uint32(self.seconds)
        return serialized.data

class ConfirmationConstraint:
    """A constraint type that signals the SSH Agent that a key requires user confirmations on each use."""
    def serialize(self):
        serialized = WriteMessage()
        serialized.write_uint8(constants.constraint.SSH_AGENT_CONSTRAIN_CONFIRM)
        return serialized.data

def fingerprint_public_key_blob(blob):
    """Generates a OpenSSH-like fingerprint for the binary data within a OpenSSH public key file.

    >>> blob = None
    >>> with open('./embedded_keys/id_rsa.pub','rb') as file:
    ...     blob = file.read().split(None,2)[1]
    ...     blob = b64decode(blob)
    >>> fingerprint_public_key_blob(blob)
    'SHA256:1zMIJ4g3aqY9qOEjBZI1Uccgsrq5g50hvlMrL7P5RW0'
    """
    hash = sha256(blob).digest()
    encoded = b64encode(hash).decode('UTF-8').rstrip('=')
    return 'SHA256:{}'.format(encoded)

def fingerprint_key(key):
    """Generates a OpenSSH-like fingerprint for the provided key.

    The key can either be an unlocked private key or the respective public key.

    >>> key = None
    >>> with open('./embedded_keys/id_rsa','rb') as file:
    ...     key = serialization.load_pem_private_key(
    ...     file.read(), backend=default_backend(), password=b'12345')
    >>> fingerprint_key(key)
    'SHA256:1zMIJ4g3aqY9qOEjBZI1Uccgsrq5g50hvlMrL7P5RW0'

    >>> fingerprint_key(key.public_key())
    'SHA256:1zMIJ4g3aqY9qOEjBZI1Uccgsrq5g50hvlMrL7P5RW0'
    """
    try: key = key.public_key()
    except: pass

    serialized = key.public_bytes(
        encoding = serialization.Encoding    .OpenSSH,
        format   = serialization.PublicFormat.OpenSSH)

    blob = b64decode(serialized.split(None,2)[1])
    return fingerprint_public_key_blob(blob)

if __name__ == '__main__':
    os.chdir('./testdata/')

    # global KP_DB
    # KP_DB = PyKeePass('./keys.kdbx','1234')

    import doctest
    doctest.testmod(optionflags=doctest.ELLIPSIS)
