import asyncio
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hmac, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import binascii
import sys

class SparkleClient(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop
        self._step = 0
        self._nonce = None
        self._server_pkey = None
        self._device_key = None
        self._device_id = b'V]*\xc7\x06\xa4_\x8e6\xec=b'
        self._device_id_hex = binascii.hexlify(self._device_id).decode()
        logging.debug("Device ID: %s" % self._device_id_hex)
        self._transport = None
        with open("serverkey.pem", "rb") as key:
            self._server_pkey = serialization.load_pem_public_key(
                key.read(),
                backend=default_backend()
            )
        logging.debug("Server key size: %s" % self._server_pkey.key_size)
        assert(self._server_pkey.key_size == 2048)
        with open("devicekey.pem", "rb") as key:
            self._device_key = serialization.load_pem_private_key(
                key.read(),
                password=None,
                backend=default_backend(),
            )
        logging.debug("Device key size: %s" % self._device_key.key_size)
        assert(self._device_key.key_size == 1024)

    def connection_made(self, transport):
        self._transport = transport
        logging.debug("Handshake step 1: Socket open")

    def data_received(self, data):
        logging.debug("Received %s data" % len(data))
        if self._step == 0:
            logging.debug("Handshake step 2: Receive(nonce())")
            assert(len(data) == 40)
            self._nonce = data
            logging.debug("Handshake step 3: Send(Encrypt(nonce + device_id))")
            response = self._nonce + self._device_id
            self._transport.write(self._encrypt_data(response))
            self._step += 1
        elif self._step == 1:
            assert(len(data) == 384)
            (encrypted_random, signature) = (data[:128], data[-256:])
            logging.debug("Handshake step 4: get session key: %s" % signature)
            random = self._decrypt_data(encrypted_random)
            (aes_key, iv, salt) = (random[:16], random[16:32], random[-8:])
            logging.debug("Handshake step 4: get session key (size: %s): AES: %s, IV: %s, SALT: %s"
                          % (len(random), aes_key, iv, salt))
            # Verify signature
            try:
                h = hmac.HMAC(random, hashes.SHA1(), backend=default_backend())
                h.update(encrypted_random)
                local_hmac = h.finalize()
                logging.debug("Local HMAC: %s" % local_hmac)
                verifier = self._server_pkey.verifier(
                    signature,
                    padding.PKCS1v15(),
                    hashes.SHA1()
                )
                verifier.update(local_hmac)
                verifier.verify()
            except InvalidSignature as e:
                logging.critical("Invalid signature: %s" % e)
                self._transport.close()

    def connection_lost(self, exc):
        self.loop.stop()
        sys.exit(1)

    def _decrypt_data(self, data):
        return self._device_key.decrypt(
            data,
            padding.PKCS1v15()
        )

    def _encrypt_data(self, data):
        return self._server_pkey.encrypt(
            data,
            padding.PKCS1v15()
        )

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: SparkleClient(loop),
                                  '127.0.0.1', 5683)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()
