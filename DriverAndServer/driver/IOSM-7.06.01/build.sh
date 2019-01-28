#!/bin/bash
make clean
rm -rf IOSM
make
mkdir IOSM
cp imc_ipc.ko ./IOSM/
cp -r ./test/scripts  ./IOSM/
chmod 777 -R IOSM
echo "install IOSM to /usr/local/bin/"
cp -rf ./IOSM  /usr/local/bin


