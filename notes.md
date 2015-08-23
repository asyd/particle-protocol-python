# Debugging the firmware

## Photon

Download https://github.com/spark/firmware/ and checkout the ``latest`` branch.

Put the photon in DFU mode and then:

    cd modules
    sudo make clean all program-dfu PLATFORM=photon DEBUG_BUILD=y

# Attach a console to the serial port

    screen /dev/ttyACM0 9600

# MISC

## How to use dfu-util as no root users

    cd /etc/udev/rules.d
    sudo wget https://gist.githubusercontent.com/monkbroc/b283bb4da8c10228a61e/raw/e59c77021b460748a9c80ef6a3d62e17f5947be1/50-particle.rules
    sudo udevadm control --reload-rules && sudo udevadm trigger

