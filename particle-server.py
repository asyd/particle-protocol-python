import asyncio
import argparse
import logging
import binascii
from src.cryptographic import CryptographicMeta
from src.backends.oscrypto_backend import CryptoOsCrypto

parser = argparse.ArgumentParser(description='Sparkle server')

parser.add_argument('--bind', dest='bind', help='Bind address', default='127.0.0.1')
parser.add_argument('--port', dest='port', help='TCP Port', default=5683)
parser.add_argument('--private-key', dest='private_key_file', help='Private key', default='server_key.pem')
parser.add_argument('--devices-keys', dest='devices_keys', help='Directory to search devices keys', default='devices')
args = None


class ParticleProtocol(asyncio.Protocol):
    """
    This is wrapper that implement:
        * handshake as describe here: https://github.com/spark/spark-protocol/blob/master/js/lib/Handshake.js#L29
    """

    def __init__(self):
        # TODO: Maybe we should add dict as ParticleProtocol inheritance?
        self._transport = None
        self._step = None
        self._device_id = None
        self._device_id_hex = None
        self._device_key = None
        self._nonce = None
        self._aes_key = None
        self._iv = None
        self._salt = None
        self._counter = 0
        self._crypto = CryptoOsCrypto()
        # Load server key
        logging.debug("Loading server key from: %s" % args.private_key_file)
        self._crypto.load_server_key(args.private_key_file)
        super().__init__()

    def connection_made(self, transport):
        # Handshake step 1: Socket opens.
        logging.debug("Client connection from %s" % transport.get_extra_info('peername')[0])
        self._transport = transport
        self._step = 0
        self._nonce = self._crypto.random(40)
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
        if self._step == 1:
            cipher = None
            # Handshake step 3: Server should read exactly 256 bytes from the socket.
            if len(data) != 256:
                logging.critical("Not enough data received from core in handshake step #3")
                self._transport.close()
            try:
                cipher = self._crypto.rsa_pkcs1v15_decrypt(data)
            except ValueError:
                self._transport.close()
            # The first 40 bytes of the message must match the previously sent nonce,
            # otherwise Server must close the connection.
            #
            # Remaining 12 bytes of message represent STM32 ID.
            (_client_nonce, self._device_id) = (cipher[:40], cipher[40:52])
            if _client_nonce != self._nonce:
                logging.critical("Invalid nonce received, closing connection.")
                self._transport.close()
            # Store an hexadecimal string of device ID
            self._device_id_hex = binascii.hexlify(self._device_id).decode()
            logging.debug("Loading device public key from %s/%s.pem" % (args.devices_keys, self._device_id_hex))
            # Server looks up STM32 ID, retrieving the Core's public RSA key.
            try:
                self._crypto.load_device_key("%s/%s.pem" % (args.devices_keys, self._device_id_hex))
                # TODO: Check key size
            # If the public key is not found, Server must close the connection.
            except Exception:
                logging.critical("Device ID %s public key not found, closing connection" % self._device_id_hex)
                self._transport.close()
            logging.info("Device ID %s connected" % self._device_id_hex)
            # Handshake step 4: Server creates secure session key
            # Server generates 40 bytes of secure random data to serve
            # as components of a session key for AES-128-CBC encryption.
            session_key = self._crypto.random(40)
            # The first 16 bytes (MSB first) will be the key, the next 16 bytes (MSB first) will be the
            # initialization vector (IV), and the final 8 bytes (MSB first) will be the salt.
            (self._aes_key, self._iv, self._salt) = (session_key[:16], session_key[16:32], session_key[-8:])
            logging.debug("AES KEY: %s, IV: %s, SALT: %s" % (self._aes_key, self._iv, self._salt))
            # Server RSA encrypts this 40-byte message using the Core's public key to create a 128-byte ciphertext.
            cipher = self._crypto.rsa_pkcs1v15_encrypt(session_key)
            logging.debug("Cipher size: %s" % len(cipher))
            # Server creates a 20-byte HMAC of the ciphertext using SHA1 and the 40 bytes generated
            # in the previous step as the HMAC key.
            hmac_result = self._crypto.hmac(session_key, cipher, CryptographicMeta.SHA1)
            logging.debug("HMAC (size: %s): %s" % (len(hmac_result), hmac_result))
            # Server signs the HMAC with its RSA private key generating a 256-byte signature.
            signature = self._crypto.rsa_pkcs1v15_sign(hmac_result)
            # Server sends 384 bytes to Core: the ciphertext then the signature.
            self.write(cipher + signature)
            self._step += 1
        elif self._step == 2:
            logging.debug("hello received from %s" % self._device_id_hex)
            # Decrypt data from hello
            (a, b, cipherdata) = (data[0], data[1], data[2::])
            hello_message = self._crypto.aes_decrypt(self._aes_key, cipherdata, self._iv)
            logging.debug("Hello message: %s %s %s"
                          % (a,
                             b,
                             binascii.hexlify(hello_message)))
            # Send our hello
            self._step += 1
        elif self._step > 3:
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


class DeviceServer(ParticleProtocol):
    def protocol_received(self, data):
        logging.info("DeviceServer hit")


if __name__ == '__main__':

    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG)

    loop = asyncio.get_event_loop()
    coro = loop.create_server(DeviceServer, args.bind, args.port)
    server = loop.run_until_complete(coro)

    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
