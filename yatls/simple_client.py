
import os
import time
import socket

import hmac
import hashlib

import binascii

import pyaes as pyaes

from yatls.crypto.structures.pre_master_secret import PreMasterSecret
from yatls.protocol.messages.alert import Alert
from yatls.protocol.messages.change_cipher_spec import ChangeCipherSpec
from yatls.protocol.records import TLSCiphertext
from yatls.protocol.records.tls_plaintext import TLSPlaintext
from yatls.protocol.messages.handshake import Handshake, ClientHello, ClientKeyExchange, Finished, Random

from yatls.crypto.x509 import x509_cert_parse, oid_lookup, asn1_decode
from yatls.crypto import rsa_pkcs1_encrypt, tls_prf


class SimpleClient(object):
    """
    A simple TLS client that can be used for testing.
    """

    VERSION = {
        "major": 3,
        "minor": 3
    }

    # We only support TLS_RSA_WITH_AES128_CBC_SHA now.
    # TODO: implement separate cipher suites and get rid of the magic constants
    CIPHER_SUITES = [
        b"\x00\x2f"
    ]

    COMPRESSION_METHODS = [
        "null"
    ]

    def __init__(self, connect_addr):
        """
        Initializes this SimpleClient object.
        :param connect_addr: the address to connect to
        """

        self._sock = None
        self._connect_addr = connect_addr
        self._random_bytes = None
        self._gmt_unix_time = None
        self._session_id = None
        self._handshake_messages_hash = None
        self._handshake_messages_prev_digest = None

        self._client_write_MAC_key = None
        self._server_write_MAC_key = None
        self._client_write_key = None
        self._server_write_key = None
        # self._client_write_IV = None
        # self._server_write_IV = None

        # self._encryption_state = None
        # self._decryption_state = None

        self._server_seq_num = None
        self._client_seq_num = None
        self._cipher_spec_changed = None

    def connect(self):
        """
        Attempts to connect and handshake with the server.
        :return:
        """

        # Initialize the random bytes (used later in the handshake)
        self._random_bytes = os.urandom(28)
        self._gmt_unix_time = int(time.time())
        self._session_id = os.urandom(32)

        # TODO: compute the digest instead of simply concatenating the messages
        self._handshake_messages_hash = hashlib.sha256()
        self._handshake_messages_prev_digest = b""
        self._server_seq_num = 0
        self._client_seq_num = 0
        self._cipher_spec_changed = False

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect(self._connect_addr)
        self._handshake()

    def close(self):
        """
        Closes the connection.
        :return:
        """

        self._send_alert("fatal", "close_notify")
        self._sock.close()

    def _send_plaintext(self, content_type, fragment):
        data = TLSPlaintext().encode(
            {
                "type": content_type,
                "version": self.VERSION,
                "fragment": fragment
            }
        )

        self._sock.send(data)

    def _send_ciphertext(self, content_type, fragment):
        raw_record = TLSPlaintext().encode(
            {
                "type": content_type,
                "version": self.VERSION,
                "fragment": fragment
            }
        )

        mac = hmac.HMAC(self._client_write_MAC_key, self._client_seq_num.to_bytes(8, "big") + raw_record,
                hashlib.sha1).digest()

        # Construct a padded plaintext for encryption
        plaintext = fragment + mac
        padding_length = 0

        while not (len(plaintext) + padding_length) % 16 == 15:
            padding_length += 1

        plaintext += padding_length.to_bytes(1, "big") * (padding_length + 1)

        iv = os.urandom(16)
        encryption_state = pyaes.AESModeOfOperationCBC(self._client_write_key, iv)
        encrypted_fragment = iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i: i+16]
            encrypted_fragment += encryption_state.encrypt(block)

        data = TLSCiphertext().encode(
            {
                "type": content_type,
                "version": self.VERSION,
                "fragment": encrypted_fragment
            }
        )

        self._client_seq_num += 1
        self._sock.send(data)

    def _send_data(self, content_type, fragment):
        if self._cipher_spec_changed:
            self._send_ciphertext(content_type, fragment)
        else:
            self._send_plaintext(content_type, fragment)

    def _recv_data(self):
        data = b""
        offset = 0
        records = []
        initial_cipher_spec_changed = self._cipher_spec_changed
        initial_server_seq_num = self._server_seq_num

        while True:
            recv = self._sock.recv(1024)
            data += recv

            if not len(recv) == 1024:
                break

        # Nasty hack to try receiving more data if decoding fails
        while True:
            try:
                while offset < len(data):
                    if not self._cipher_spec_changed:
                        size, record = TLSPlaintext().decode(data, offset)
                        offset += size

                    else:
                        size, encrypted_record = TLSCiphertext().decode(data, offset)
                        offset += size

                        iv = encrypted_record["fragment"][0:16]
                        ciphertext = encrypted_record["fragment"][16:]

                        # Initialize the decryption
                        decrypt_state = pyaes.AESModeOfOperationCBC(self._server_write_key, iv)

                        plaintext = b""
                        for i in range(0, len(ciphertext), 16):
                            block = ciphertext[i: i+16]
                            plaintext += decrypt_state.decrypt(block)

                        # Remove the plaintext padding
                        padding_length = plaintext[-1]
                        plaintext = plaintext[:-padding_length-1]

                        fragment = plaintext[:-20]
                        mac = plaintext[-20:]

                        record = {
                            "type": encrypted_record["type"],
                            "version": encrypted_record["version"],
                            "fragment": fragment
                        }

                        raw_record = TLSPlaintext().encode(record)
                        mac_verify = hmac.HMAC(self._server_write_MAC_key,
                                               self._server_seq_num.to_bytes(8, "big") + raw_record,
                                               hashlib.sha1).digest()

                        if not mac == mac_verify:
                            raise IOError("Invalid MAC")

                        self._server_seq_num += 1

                    if record["type"] == "alert":
                        alert = Alert().decode(record["fragment"])[1]

                        if alert["level"] == "fatal":
                            raise IOError("TLS Alert {}".format(alert))
                        else:
                            print("TLS Alert Warning {}".format(alert))

                    elif record["type"] == "change_cipher_spec":
                        self._cipher_spec_changed = True

                    else:
                        records.append(record)

                return records
            except IndexError:
                records = []
                offset = 0
                self._cipher_spec_changed = initial_cipher_spec_changed
                self._server_seq_num = initial_server_seq_num
                data += self._sock.recv(1024)

    def _send_handshake(self, handshake_type, body, encrypted=False):
        data = Handshake().encode(
            {
                "handshake_type": handshake_type,
                "body": body
            }
        )

        print("->", handshake_type)
        self._handshake_messages_hash.update(data)

        if not encrypted and not self._cipher_spec_changed:
            self._send_plaintext("handshake", data)
        else:
            self._send_ciphertext("handshake", data)

    def _recv_handshake(self):
        data = b""
        offset = 0
        messages = []
        records = self._recv_data()

        for record in records:
            if not record["type"] == "handshake":
                raise ValueError("Expected a handshake record")

            data += record["fragment"]

        while offset < len(data):
            size, message = Handshake().decode_auto(data, offset)
            self._handshake_messages_prev_digest = self._handshake_messages_hash.digest()
            self._handshake_messages_hash.update(data[offset: offset + size])
            offset += size
            messages.append(message)
            print("<-", message[0])

        return messages

    def _send_client_hello(self):
        data = ClientHello().encode(
            {
                "client_version": self.VERSION,
                "random": {
                    "gmt_unix_time": self._gmt_unix_time,
                    "random_bytes": self._random_bytes
                },

                "session_id": self._session_id,
                "cipher_suites": self.CIPHER_SUITES,
                "compression_methods": self.COMPRESSION_METHODS,
                "extensions": []
            }
        )

        self._send_handshake("client_hello", data)

    def _send_client_key_exchange(self, encrypted_pre_master_secret):
        data = ClientKeyExchange().encode(
            {
                "exchange_keys": {
                    "encrypted": encrypted_pre_master_secret
                }
            }
        )

        self._send_handshake("client_key_exchange", data)

    def _send_change_cipher_spec(self):
        data = ChangeCipherSpec().encode(
            {
                "type": "change_cipher_spec"
            }
        )

        self._send_plaintext("change_cipher_spec", data)

    def _send_finished(self, verify_data):
        data = Finished().encode(
            {
                "verify_data": verify_data
            }
        )

        self._send_handshake("finished", data, encrypted=True)

    def _send_application_data(self, data):
        self._send_data("application_data", data)

    def _recv_application_data(self):
        data = b""
        records = self._recv_data()

        for record in records:
            if record["type"] == "application_data":
                data += record["fragment"]
            else:
                raise IOError("Unexpected TLS record {}".format(record))

        return data

    def _send_alert(self, level, description):
        data = Alert().encode(
            {
                "level": level,
                "description": description
            }
        )

        self._send_data("alert", data)

    def send(self, data):
        """
        Sends raw data to the server (with fragmentation).
        :param data: the data to send
        :return:
        """

        for i in range(0, len(data), 2**14):
            fragment = data[i: i+2**14]
            self._send_application_data(fragment)

    def recv(self):
        """
        Waits for raw data from the server
        :return: the received data
        """

        data = b""

        while True:
            recv = self._recv_application_data()
            data += recv

            if not recv:
                break

        return data

    def _handshake(self):
        server_random = None
        server_rsa_pubkey = None

        pre_master_secret = PreMasterSecret().encode(
            {
                "client_version": self.VERSION,
                "random": os.urandom(46)
            }
        )

        # Send a ClientHello and wait for further handshake messages
        self._send_client_hello()
        handshake_messages = self._recv_handshake()

        # Process the handshake messages
        for message_type, message in handshake_messages:
            if message_type == "server_hello":
                server_random = Random().encode(message["random"])

            elif message_type == "certificate":
                print("Certificates:")

                certificates = [x509_cert_parse(raw_cert) for raw_cert in message["certificate_list"]]
                for certificate in certificates:
                    print("\t", certificate["subject"])

                server_pubkey = certificates[0]["subject_key_info"]
                pubkey_algorithm = server_pubkey[0]
                raw_pubkey = server_pubkey[1]

                if not oid_lookup(pubkey_algorithm[0]) == "rsaEncryption":
                    raise ValueError("Expected an RSA public key")

                server_rsa_pubkey = asn1_decode(raw_pubkey)[1]

        # Encrypt the pre-master secret
        modulus, exponent = server_rsa_pubkey
        encrypted_pre_master_secret = rsa_pkcs1_encrypt(pre_master_secret, modulus, exponent)

        # Calculate the master secret
        client_random = Random().encode(
            {
                "gmt_unix_time": self._gmt_unix_time,
                "random_bytes": self._random_bytes
            }
        )

        master_secret = tls_prf(pre_master_secret, b"master secret", client_random + server_random, 48)

        # Derive the key block
        # For TLS_RSA_WITH_AES128_CBC_SHA, mac_key_length = 20, enc_key_length = 16, fixed_iv_length = 16
        key_block = tls_prf(master_secret, b"key expansion", server_random + client_random, 104)

        self._client_write_MAC_key = key_block[0: 20]
        self._server_write_MAC_key = key_block[20: 40]
        self._client_write_key = key_block[40: 56]
        self._server_write_key = key_block[56: 72]
        # self._client_write_IV = key_block[72: 88]
        # self._server_write_IV = key_block[88: 104]

        # Continue the handshake
        self._send_client_key_exchange(encrypted_pre_master_secret)
        self._send_change_cipher_spec()

        self._client_seq_num = 0
        self._server_seq_num = 0
        verify_data = tls_prf(master_secret, b"client finished", self._handshake_messages_hash.digest(), 12)
        self._send_finished(verify_data)

        # Wait for a response (Finished)
        response = self._recv_handshake()
        for message_type, message in response:
            if message_type == "finished":
                server_verify_data = tls_prf(master_secret, b"server finished",
                                             self._handshake_messages_prev_digest, 12)

                if not message["verify_data"] == server_verify_data:
                    raise IOError("Invalid verify data")
