#!/bin/bash

cd client
./compile_all.sh
cd - > /dev/null
cd server
./compile_all.sh
cd - > /dev/null
