import asyncio
import argparse
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


parser = argparse.ArgumentParser(description='Sparkle server')

parser.add_argument('--bind', dest='bind', help='Bind address', default='127.0.0.1')
parser.add_argument('--port', dest='port', help='TCP Port', default=5683)
parser.add_argument('--private-key', dest='private_key_file', help='Private key', default='privatekey.pem')

args = None


class SparkleProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        self._step = 0

    def data_received(self, data):
        print('Data received: {!r}'.format(data.decode()))
        self.transport.write(data)
        self._step += 1

    def protocol_received(self, data):
        raise NotImplementedError


class DeviceServer(SparkleProtocol):
    def protocol_received(self, data):
        print("toto")


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
    coro = loop.create_server(SparkleProtocol, args.bind, args.port)
    server = loop.run_until_complete(coro)

    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass