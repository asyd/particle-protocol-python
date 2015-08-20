import asyncio
import argparse
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hmac, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from os import urandom
import binascii
import rsa

parser = argparse.ArgumentParser(description='Sparkle server')

parser.add_argument('--bind', dest='bind', help='Bind address', default='127.0.0.1')
parser.add_argument('--port', dest='port', help='TCP Port', default=5683)
parser.add_argument('--private-key', dest='private_key_file', help='Private key', default='privatekey.pem')
parser.add_argument('--devices-keys', dest='devices_keys', help='Directory to search devices keys', default='devices')

args = None


class SparkleProtocol(asyncio.Protocol):
    """
    This is wrapper that implement:
        * handshake as describe here: https://github.com/spark/spark-protocol/blob/master/js/lib/Handshake.js#L29
    """
    def __init__(self):
        logging.debug("SparkleProtocol initialisation")
        self._transport = None
        self._step = None
        self._device_id = None
        self._device_id_hex = None
        self._device_key = None
        self._nonce = None
        super().__init__()

    def connection_made(self, transport):
        # Handshake step 1: Socket opens.
        logging.debug("Client connection from %s" % transport.get_extra_info('peername')[0])
        self._transport = transport
        self._step = 0
        self._nonce = urandom(40)
        # Handshake step 2: Server responds with 40 bytes of random data as a nonce.
        if self._step == 0:
            logging.debug("Generated nonce: %s" % self._nonce)
            self.write(self._nonce)
            self._step += 1

    def connection_lost(self, exc):
        logging.debug("Connection lost with device ID: %s (%s)" %
                      (self._device_id_hex, self._transport.get_extra_info('peername')[0]))

    def data_received(self, data):
        logging.debug("Data received (%s) %s: %s" % (self._step, len(data), data))
        logging.debug("Read %s data" % len(data))
        if self._step == 1:
            ciphertext = None
            # Handshake step 3: Server should read exactly 256 bytes from the socket.
            if len(data) != 256:
                logging.critical("Not enough data received from core in handshake step #3")
                self._transport.close()
            try:
                ciphertext = self._decrypt_data(data)
            except ValueError:
                self._transport.close()
            # The first 40 bytes of the message must match the previously sent nonce,
            # otherwise Server must close the connection.
            #
            # Remaining 12 bytes of message represent STM32 ID.
            (_client_nonce, _client_id) = (ciphertext[:40], ciphertext[-12:])
            if _client_nonce != self._nonce:
                logging.critical("Invalid nonce received, closing connection.")
                self._transport.close()
            self._device_id = _client_id
            # Store an hexadecimal string of device ID
            self._device_id_hex = binascii.hexlify(_client_id).decode()
            logging.debug("Loading device public key from %s/%s.pem" % (args.devices_keys, self._device_id_hex))
            # Server looks up STM32 ID, retrieving the Core's public RSA key.
            try:
                with open("%s/%s.pem" % (args.devices_keys, self._device_id_hex), "rb") as key:
                    self._device_key = serialization.load_pem_public_key(
                        key.read(),
                        backend=default_backend()
                    )
                logging.debug("Device ID %s key size is: %s" % (self._device_id_hex, self._device_key.key_size))
                if self._device_key.key_size != 1024:
                    logging.critical("Invalid key size! Closing connection")
                    self._transport.close()
            # If the public key is not found, Server must close the connection.
            except FileNotFoundError:
                logging.critical("Device ID %s public key not found, closing connection" % self._device_id_hex)
                self._transport.close()
            logging.info("Device ID %s connected" % self._device_id_hex)
            # Handshake step 4: Server creates secure session key
            # Server generates 40 bytes of secure random data to serve
            # as components of a session key for AES-128-CBC encryption.
            session_key = urandom(40)
            # The first 16 bytes (MSB first) will be the key, the next 16 bytes (MSB first) will be the
            # initialization vector (IV), and the final 8 bytes (MSB first) will be the salt.
            (aes_key, iv, salt) = (session_key[:16], session_key[16:32], session_key[-8:])
            logging.debug("AES KEY: %s, IV: %s, SALT: %s" % (aes_key, iv, salt))
            # Server RSA encrypts this 40-byte message using the Core's public key to create a 128-byte ciphertext.
            ciphertext = self._encrypt_data(session_key)
            logging.debug("Ciphertext size: %s" % len(ciphertext))
            # Server creates a 20-byte HMAC of the ciphertext using SHA1 and the 40 bytes generated
            # in the previous step as the HMAC key.
            hash = hmac.HMAC(session_key, hashes.SHA1(), backend=default_backend())
            hash.update(ciphertext)
            hmac_result = hash.finalize()
            logging.debug("HMAC (size: %s): %s" % (len(hmac_result), hmac_result))
            # Server signs the HMAC with its RSA private key generating a 256-byte signature.
            signature = self._sign_data(hmac_result)
            logging.debug("Signature size: %s" % len(signature))
            # Server sends 384 bytes to Core: the ciphertext then the signature.
            self.write(ciphertext + signature)
            self._step += 1
        elif self._step > 2:
            return self.protocol_received(data)

    def write(self, data):
        logging.debug("Sending %s bytes to %s (%s), step: %s" % (
            len(data),
            self._device_id_hex,
            self._transport.get_extra_info('peername')[0],
            self._step
        ))
        self._transport.write(data)

    def protocol_received(self, data):
        raise NotImplementedError

    @staticmethod
    def _sign_data(data):
        """
        Hmm there is something strange here, check: https://github.com/spark/spark-protocol/blob/master/js/lib/ICrypto.js#L173
        The function sign is not used, but encrypt is. So i need to create a rsa (yeah, another module) instance to cipher
        data using the private key
        """
        logging.debug("Loading private key from: %s" % args.private_key_file)
        with open(args.private_key_file, "rb") as key_file:
            keydata = key_file.read()
        key = rsa.PrivateKey.load_pkcs1(keydata)
        return rsa.encrypt(data, key)



    @staticmethod
    def _decrypt_data(data):
        clear_text = args.private_key.decrypt(
            data,
            padding.PKCS1v15()
        )
        return clear_text

    def _encrypt_data(self, data):
        return self._device_key.encrypt(
            data,
            padding.PKCS1v15()
        )


class DeviceServer(SparkleProtocol):
    def protocol_received(self, data):
        logging.info("DeviceServer hit")


def server_init():
    logging.debug("Server initialization")
    logging.debug("Loading private key: %s" % args.private_key_file)
    with open(args.private_key_file, "rb") as pk:
        args.private_key = serialization.load_pem_private_key(
            pk.read(),
            password=None,
            backend=default_backend()
        )
    # Key size MUST BE 2048
    assert(args.private_key.key_size == 2048)

if __name__ == '__main__':

    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG)
    server_init()

    loop = asyncio.get_event_loop()
    coro = loop.create_server(DeviceServer, args.bind, args.port)
    server = loop.run_until_complete(coro)

    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass