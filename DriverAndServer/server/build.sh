#!/bin/bash
make clean

make

##for systemd
echo "install mdm-server and mdm-server.service"
cp -f mdm-server /lib/systemd/system/mdm-server
cp -f mdm-server.service /lib/systemd/system/mdm-server.service
cd /lib/systemd/system

systemctl disable  mdm-server.service
ln -s /lib/systemd/system/mdm-server.service /etc/systemd/system/
systemctl enable mdm-server.service
