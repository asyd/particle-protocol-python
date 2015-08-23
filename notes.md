# Debugging the firmware

## Photon

Download https://github.com/spark/firmware/ and checkout the ``latest`` branch.

    cd modules
    make clean all PLATFORM=photon DEBUG_BUILD=y

Put the photon in DFU mode and then:

    sudo make all program-dfu PLATFORM=photon DEBUG_BUILD=y