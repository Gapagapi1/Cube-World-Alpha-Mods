#!/bin/bash

i686-w64-mingw32-gcc -shared -O2 -s -static-libgcc -o ClientConfig.dll cw-client-config.c -lws2_32

i686-w64-mingw32-gcc -DVERBOSE -shared -O2 -s -static-libgcc -o ClientConfigDebug.dll cw-client-config.c -lws2_32
