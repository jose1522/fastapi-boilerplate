from cryptography.fernet import Fernet
from settings import settings


class EncryptedString(str):
    def __init__(self, text: str):
        super().__init__()
        self.text = text


class HashedString(str):
    def __init__(self, text: str):
        super().__init__()
        self.text = text

class Cipher:
    def __init__(self):
        self.__f = Fernet(settings.DB_ENCRYPTION_KEY.encode('utf8'))

    @classmethod
    def encryptString(cls, value: str) -> str:
        e = cls()
        value = e.__f.encrypt(bytes(value, encoding="utf8"))
        return value.decode('utf8')

    @classmethod
    def decryptString(cls, value: str) -> EncryptedString:
        e = cls()
        value = e.__f.decrypt(bytes(value.encode('utf8')))
        value = EncryptedString(value.decode('utf8'))
        return value