__author__ = 'asyd'
import oscrypto.asymmetric
import oscrypto.symmetric

from src.cryptographic import CryptographicMeta


class CryptoOsCrypto(CryptographicMeta):
    """
    This class use oscrypto (https://github.com/wbond/oscrypto) as backend
    """
    def load_device_key(self, filename):
        self.device_public_key = oscrypto.asymmetric.load_public_key(filename)

    def load_server_key(self, filename):
        self.server_secret_key = oscrypto.asymmetric.load_private_key(filename)

    def rsa_pkcs1v15_encrypt(self, data):
        return oscrypto.asymmetric.rsa_pkcs1v15_encrypt(self.device_public_key, data)

    def rsa_pkcs1v15_decrypt(self, data):
        return oscrypto.asymmetric.rsa_pkcs1v15_decrypt(self.server_secret_key, data)

    @staticmethod
    def aes_encrypt(key, data, iv):
        # TODO: we problably must return [1]
        return oscrypto.symmetric.aes_cbc_no_padding_encrypt(key, data, iv)

    @staticmethod
    def aes_decrypt(key, data, iv):
        return oscrypto.symmetric.aes_cbc_no_padding_decrypt(key, data, iv)

    def rsa_pkcs1v15_sign(self, data, algorithm=None):
        if algorithm is None:
            algorithm = 'raw'
        return oscrypto.asymmetric.rsa_pkcs1v15_sign(self.server_secret_key, data, algorithm)
