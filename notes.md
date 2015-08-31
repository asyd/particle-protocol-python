# Debugging the firmware

## Photon

Download https://github.com/spark/firmware/ and checkout the ``latest`` branch.

Add the following line in ``user/src/application.cpp``, outside the setup and loop functions:

    SerialDebugOutput debugOutput;

Put the photon in DFU mode and then:

    cd modules
    make -C .. clean && make clean all program-dfu PLATFORM=photon DEBUG_BUILD=y

As far the make upload 3 files it's ok, even if the last one failed on dfu-utils.

# Attach a console to the serial port

    screen /dev/ttyACM0 9600

or

    particle serial monitor

If you have trouble with the serial monitor, check if you have a process ModemManager running, in that case disabled
it with the following commands:

    systemctl stop ModemManager
    systemctl disable ModemManager

# Tips

## How to use dfu-util as no root user

    cd /etc/udev/rules.d
    sudo wget https://gist.githubusercontent.com/monkbroc/b283bb4da8c10228a61e/raw/e59c77021b460748a9c80ef6a3d62e17f5947be1/50-particle.rules
    sudo udevadm control --reload-rules && sudo udevadm trigger

