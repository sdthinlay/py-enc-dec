import unittest

from app.encrypt import Encryptor
from app.decrypt import Decryptor


class TestEncryptionDecryption(unittest.TestCase):
    def setUp(self) -> None:
        self.plaintext_input = 'Harry Potter and the Prisoner of Azkaban'
        self.plaintext_key = 'hocus pocus'

    def test_can_instantiate_decryptor_object(self):
        enc = Encryptor(self.plaintext_key)
        dec = Decryptor(self.plaintext_key)
        encrypted_data = enc.encrypt(self.plaintext_input)
        decrypted_data = dec.decrypt(encrypted_data)
        self.assertEqual(decrypted_data.decode(), self.plaintext_input)
