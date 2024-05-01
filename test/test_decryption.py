import binascii
import unittest
# Import cryptography library
from app.decrypt import Decryptor


class TestAdapter:
    def __init__(self, _input):
        self.encoded_data = _input

    def read_data(self) -> bytes:
        return self.encoded_data


class TestDecryption(unittest.TestCase):
    def setUp(self) -> None:
        self.encoded_data = \
            b'gAAAAABhUyGZc5rwM_lqyPwW7JQ07q-MiXEYeOMBg7iY_ua8Qs5Ro-qwyWVb0ME-3gioswBbidhrtPjmrRD4pw4FJuZgpwy0oA=='
        self.plaintext_key = 'simsalabim'

    def test_can_instantiate_decryptor_object(self):
        try:
            _ = Decryptor(self.plaintext_key)
            self.assertTrue(True)
        except binascii.Error:
            self.assertFalse(True)

    def test_decrypt_bytes_expect_bytes(self):
        dec = Decryptor(self.plaintext_key)
        try:
            decrypted_data = dec.decrypt(self.encoded_data)
            self.assertIsInstance(decrypted_data, bytes)
        except (TypeError, InvalidToken):
            self.assertFalse(True)

    def test_decrypt_adapter_expected_bytes(self):
        adapter = TestAdapter(self.encoded_data)
        enc = Decryptor(self.plaintext_key)
        try:
            encrypted_data = enc.decrypt(adapter)
            self.assertIsInstance(encrypted_data, bytes)
        except TypeError:
            self.assertFalse(True)
