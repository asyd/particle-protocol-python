__author__ = 'nadley'

import socketserver
import sys
import binascii
from datetime import datetime
from os import urandom
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import logging


class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def setup(self):
        self.private_key_path = "../privatekey.pem"
        self.private_key = None
        self._load_server_private_key()

    def handle(self):
        while True:
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            print("{} : Incoming request from : {} on socket port : {}".format(now, self.client_address[0],
                                                                               self.client_address[1]))

            nonce = self._generate_nonce()
            print("Nonce is :  {}".format(nonce))
            print("Send NONCE")
            quantity = self.request.send(nonce)
            print("Quantity of data : {}".format(quantity))
            response_data = self.request.recv(256)
            print("Response {}".format(response_data))
            print("Response size : {}".format(sys.getsizeof(response_data)))
            print(len(response_data))

            decrypted = self._decrypt_data(response_data)
            # print(type(decrypted))
            print("Decrypted value is : {}".format(decrypted))

            print("Id is : {}".format(binascii.hexlify(decrypted[-12:])))



            # self.request is the TCP socket connected to the client
            # self.data = self.request.recv(1024).strip()
            # print("{} wrote:".format(self.client_address[0]))
            # print(self.data)

    def finish(self):
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("{} finishing socket".format(now))
        self.request.close()

    def _generate_nonce(self):
        return urandom(40)

    def _load_server_private_key(self):
        # logging.debug("Loading private key %(self.private_key_path)s" % locals())
        with open(self.private_key_path, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        logging.debug("Private key size: %s" % self.private_key.size())

    def _load_server_public_key(self):
        with open("../ServerKeys/cloud_public.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key

    def _encrypt_data(self, data):
        ciphertext = self.public_key.encrypt(
            data.encode(),
            padding.PKCS1v15()
        )
        return ciphertext

    def _decrypt_data(self, ciphertext):
        clear_text = self.private_key.decrypt(
            ciphertext,
            padding.PKCS1v15()
        )
        return clear_text


if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 5683
    logging.basicConfig(level=logging.DEBUG)

    # Create the server
    server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)
    server.daemon_threads = True

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()
