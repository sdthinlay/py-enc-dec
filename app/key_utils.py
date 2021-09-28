import base64


def key32(key: str) -> str:
    """
    Pad the key with spaces (if necessary) so we can create a
    key length of 32. If the key is longer than 32 characters,
    it will be truncated to exactly 32 characters.

    :param key: Key to pad and truncate
    :return: Padded and truncated key
    """
    if len(key) < 32:
        key += ' ' * 32
    return key[:32]


def key64(key: str) -> bytes:
    """
    Use encode on the key to create a bytes object, then
    safely encode in Base-64.

    :param key: Key to encode into Base-64
    :return: Key encoded in Base-64
    """
    return base64.urlsafe_b64encode(key.encode())
