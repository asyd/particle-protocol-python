import asyncio
import argparse
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from os import urandom

parser = argparse.ArgumentParser(description='Sparkle server')

parser.add_argument('--bind', dest='bind', help='Bind address', default='127.0.0.1')
parser.add_argument('--port', dest='port', help='TCP Port', default=5683)
parser.add_argument('--private-key', dest='private_key_file', help='Private key', default='privatekey.pem')

args = None


class SparkleProtocol(asyncio.Protocol):

    def __init__(self):
        logging.debug("SparkleProtocol initialisation")
        self._transport = None
        self._step = None
        self._client_id = None
        self._nonce = None
        super().__init__()

    def connection_made(self, transport):
        logging.debug("connect from %s" % transport.get_extra_info('peername')[0])
        logging.debug("New connection")
        self._transport = transport
        self._step = 0
        self._nonce = urandom(40)
        # Handshake step 0: send nonce
        if self._step == 0:
            logging.debug("Generated nonce: %s" % self._nonce)
            self._transport.write(self._nonce)
            self._step += 1

    def data_received(self, data):
        logging.debug("Data received (%s) %s: %s" % (self._step, len(data), data))
        logging.debug("Read %s data" % len(data))
        # Handshake step 1: reply with nonce + device_id encrypted with public server key
        if self._step == 1:
            assert(len(data) == 256)
            response = self._decrypt_data(data)
            (_client_nonce, _client_id) = (response[:40], response[-12:])
            if _client_nonce != self._nonce:
                logging.critical("Invalid nonce received, closing connection.")
                self._transport.close()
            self._client_id = _client_id.decode('ASCII')
            logging.debug("Device ID %s connected" % self._client_id)
            self._step += 1
        elif self._step == 2:
            random = urandom(40)
            (aes_key, iv, salt) = (random[:16], random[16:32], random[-8:])
            logging.debug("AES KEY: %s, IV: %s, SALT: %s" % (aes_key, iv, salt))
            self._transport.write(b'pong')
            self._step += 1
        elif self._step > 2:
            return self.protocol_received(data)

    def protocol_received(self, data):
        raise NotImplementedError

    @staticmethod
    def _decrypt_data(data):
        clear_text = args.private_key.decrypt(
            data,
            padding.PKCS1v15()
        )
        return clear_text


class DeviceServer(SparkleProtocol):
    def protocol_received(self, data):
        self._transport.write(b'pong')
        print(data.decode('ASCII'))


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