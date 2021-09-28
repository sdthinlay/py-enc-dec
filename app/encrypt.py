# Import cryptography library

from app.key_utils import key32, key64


class Encryptor:
    def __init__(self, key):
        key32_ = key32(key)
        key64_ = key64(key32_)

        # We need to do something with the key...

    def _encrypt(self, data: bytes) -> bytes:
        """
        This method performs the actual encryption on {data}..

        :param data: Data to be encrypted
        :return: Encrypted data
        """
        raise NotImplementedError()

    def encrypt(self, data) -> bytes:
        """
        This method takes data and encrypts it using the key that
        was passed in through the initialiser. The parameter {data}
        can either be a string, which will be encrypted as such
        (after converting it to bytes), or an object that has the
        method {read_data}, which takes no arguments but *must*
        return a bytes object.

        :param data: Data to encrypt
        :return: Encrypted data as a bytes object
        """
        if isinstance(data, str):
            data = data.encode()
        elif hasattr(data, 'read_data'):
            data = data.read_data()
        else:
            raise TypeError('Invalid input type')

        return self._encrypt(data)
