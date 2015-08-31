This a particle server implementation written in Python.

# Requirements

All you need is python3 (tested with 3.4.3 on Debian Sid), virtualenv and Internet connection.

# Installation using virtualenv

    virtualenv -p /usr/bin/python3 particle-python
    cd particle-python
    git clone https://github.com/asyd/particle-protocol-python
    ./bin/pip install git+git://github.com/wbond/asn1crypto.git
    ./bin/pip install git+git://github.com/wbond/oscrypto.git
    ./bin/pip install -r particle-protocol-python/requirements.txt 

# Put devices key

Before manage a device by your own server, you must add it's public key to the ``devices`` directory:

  * Install [particle-cli](https://github.com/spark/particle-cli#installing)
  * Put your device in [Wifi Network Reset](https://docs.particle.io/guide/getting-started/modes/core/#wifi-network-reset) mode
  * Execute ``particle serial identify`` (you should have something like 25003e001747343338363332)
  * Put your device in [DFU mode](https://docs.particle.io/guide/getting-started/modes/core/#dfu-mode-device-firmware-upgrade-)
  * Execute (in /tmp directory for example) ``particle keys save 25003e001747343338363332``
  * Copy the file ``25003e001747343338363332.pub.pem`` to ``particle-python/particle-protocol-python/devices/25003e001747343338363332.pem`` (You must remove the .pub. part!)
 
# Before running the server

## Create the server key

    cd particle-protocol-python
    openssl genrsa -out server_key.pem 2048
    openssl rsa -in server_key.pem -pubout -out server_pub.pem

## Define device server

Upload the server public key and its IP (the one you run the server) :

  * Put your device in [DFU mode](https://docs.particle.io/guide/getting-started/modes/core/#dfu-mode-device-firmware-upgrade-)
  * Execute: ``particle keys server server_pub.pem 192.168.0.18``

# Run server

    ./bin/python ./particle-protocol-python/particle-server.py --bind 0.0.0.0