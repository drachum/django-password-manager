import base64
from Crypto.Cipher import AES
from Crypto import Random
from hashlib import sha256


class CipherInterface(object):
    def encrypt(self, raw):
        return NotImplementedError('Cipher derived classes must implement '
                                   'encrypt method')

    def decrypt(self, enc):
        return NotImplementedError('Cipher derived classes must implement '
                                   'decrypt method')


class AESCipher(CipherInterface):
    def __init__(self, key):
        self.key = sha256(key).digest()

    def _pad(self, s):
        BS = AES.block_size
        return s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()

    def _unpad(self, s):
        return s[:-ord(s[len(s) - 1:])]

    def encrypt(self, raw):
        # Accept str and bytes
        if isinstance(raw, str):
            raw = raw.encode()
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode()

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[16:])).decode()


class AES256Cipher(AESCipher):
    def __init__(self, key):
        # Accept str and bytes
        if isinstance(key, str):
            key = key.encode()
        self.key = sha256(key).digest()


def random_key(nbytes):
    return Random.get_random_bytes(nbytes)


DefaultCipher = AES256Cipher
