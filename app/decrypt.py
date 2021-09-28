from cryptography.fernet import Fernet, InvalidToken

from app.key_utils import key32, key64


class Decryptor:
    def __init__(self, key):
        key32_ = key32(key)
        key64_ = key64(key32_)
        self.__fernet = Fernet(key64_)

    def _decrypt(self, data: bytes) -> bytes:
        """
        This method performs the actual decryption on the {data} object.
        It raises InvalidToken if it can't decrypt properly.

        :param data: Data to be decrypted
        :return: Decrypted data
        """
        try:
            decrypted_data = self.__fernet.decrypt(data)
            return decrypted_data
        except InvalidToken:
            print('Error: invalid key, decryption not possible!')
            raise

    def decrypt(self, data) -> bytes:
        """
        This method takes encrypted data in the form of a bytes object,
        and decrypts it using the key that was passed in through the
        initialiser. If the parameter {data} is a bytes object, it will
        be used to decrypt. It can also be an object that has the method
        {read_data}, which takes no arguments and returns a bytes object.
        If it is neither, a TypeError is raised.

        :param data: Encrypted data
        :return: Decrypted data as a bytes object
        """
        if hasattr(data, 'read_data'):
            data = data.read_data()
        elif not isinstance(data, bytes):
            raise TypeError('Invalid input type')

        return self._decrypt(data)
