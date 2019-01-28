#!/bin/bash

cd $PWD/server/
./build.sh
cd ..
cd $PWD/driver/IOSM-7.06.01/
./build.sh
cd ../../
