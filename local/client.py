import asyncio
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import random
import string


class SparkleClient(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop
        self._step = 0
        self._nonce = None
        self._public_key = None
        self._device_id = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(12))
        logging.debug("Generated device id: %s" % self._device_id)
        self._transport = None
        with open("publickey.pem", "rb") as key:
            self._public_key = serialization.load_pem_public_key(
                key.read(),
                backend=default_backend()
            )

    def connection_made(self, transport):
        self._transport = transport

    def data_received(self, data):
        logging.debug("Received %s data" % len(data))
        if self._step == 0:
            self._nonce = data
            response = self._nonce + bytes(self._device_id, 'ASCII')
            logging.debug("%s" % response.__class__)
            self._transport.write(self._encrypt_data(response))
            self._step += 1

    def connection_lost(self, exc):
        self.loop.stop()

    def _encrypt_data(self, data):
        ciphertext = self._public_key.encrypt(
            data,
            padding.PKCS1v15()
        )
        return ciphertext

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: SparkleClient(loop),
                                  '127.0.0.1', 5683)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()