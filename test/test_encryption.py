import binascii
import unittest

from app.encrypt import Encryptor


class TestAdapter:
    def __init__(self, _input):
        self.plaintext_input = _input

    def read_data(self) -> bytes:
        return self.plaintext_input.encode()


class TestEncryption(unittest.TestCase):
    def setUp(self) -> None:
        self.plaintext_input = 'Harry Potter'
        self.plaintext_key = 'abacadabra'

    def test_can_instantiate_encryptor_object(self):
        try:
            _ = Encryptor(self.plaintext_key)
            self.assertTrue(True)
        except binascii.Error:
            self.assertFalse(True)

    def test_encrypt_string_expect_bytes(self):
        enc = Encryptor(self.plaintext_key)
        try:
            encrypted_data = enc.encrypt(self.plaintext_input)
            self.assertIsInstance(encrypted_data, bytes)
        except TypeError:
            self.assertFalse(True)

    def test_encrypt_adapter_expected_bytes(self):
        adapter = TestAdapter(self.plaintext_input)
        enc = Encryptor(self.plaintext_key)
        try:
            encrypted_data = enc.encrypt(adapter)
            self.assertIsInstance(encrypted_data, bytes)
        except TypeError:
            self.assertFalse(True)
