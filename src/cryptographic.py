__author__ = 'asyd'

from abc import ABCMeta, abstractmethod
import os
import hmac
import hashlib


class CryptographicException(Exception):
    pass


class CryptographicMeta(metaclass=ABCMeta):
    MD5 = 0
    SHA1 = 1
    SHA256 = 2
    """
    Abstract class to manage different backends. We wrote this abstract class because Particle protocol have sometimes
    very low level of deprecated usage of cryptographic functions.

    Here the list of library we tried:
    - rsa
    - oscrypto
    - cryptrographic.hazmat

    Therefore, we don't want to change a lot of code each time we need to test a different cryptographic library
    """

    def __init__(self):
        """
        :return:
        """
        self.server_secret_key = None
        self.device_public_key = None

    @staticmethod
    def random(size):
        """
        :param size:
        :return:
        """
        return os.urandom(size)

    @abstractmethod
    def load_device_key(self, filename):
        """
        Load device public key from file
        :param filename: PEM file of device key, usually store in devices/ directory
        :return:
        """
        pass

    @abstractmethod
    def load_server_key(self, filename):
        pass

    @staticmethod
    @abstractmethod
    def aes_encrypt(key, data, iv):
        pass

    @staticmethod
    @abstractmethod
    def aes_decrypt(key, data, iv):
        pass

    @abstractmethod
    def rsa_pkcs1v15_sign(self, data, algorithm):
        pass

    @abstractmethod
    def rsa_pkcs1v15_encrypt(self, data):
        pass

    @abstractmethod
    def rsa_pkcs1v15_decrypt(self, data):
        """
        Decrypt RSA data received from device, using PKCS#1v15 Padding
        :param data:
        :return: Decrypted data
        """
        pass

    @staticmethod
    def hmac(key, data, algorithm):
        """
        Compute a HMAC of data, using key and hashes algorithm
        :param key:
        :param data:
        :param algorithm:
        :return:
        """
        if algorithm == CryptographicMeta.SHA1:
            algorithm = hashlib.sha1
        else:
            raise NotImplementedError
        return hmac.new(key, data, algorithm).digest()
