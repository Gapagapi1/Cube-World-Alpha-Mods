#!/bin/bash

i686-w64-mingw32-gcc -shared -O2 -s -o GracefulShutdown.dll cw-graceful-shutdown.c
i686-w64-mingw32-gcc -shared -O2 -s -static-libgcc -o Config.dll cw-config.c -lws2_32
