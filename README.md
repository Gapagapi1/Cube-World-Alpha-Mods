# Cube World Alpha Server Mods

DLL mods for the Cube World Alpha dedicated server.

Server mods require the [Cube World Server Mod Launcher](https://github.com/coremaze/Cube-World-Server-Mod-Launcher) (Download it here: [prerelease2](https://github.com/coremaze/Cube-World-Server-Mod-Launcher/releases/tag/prerelease2))

Client mods require the [Cube World Mod Launcher](https://github.com/coremaze/Cube-World-Mod-Launcher/tree/v1.5) (Download it here: [v1.5](https://github.com/coremaze/Cube-World-Mod-Launcher/releases/tag/v1.5))

Go check the [Releases](https://github.com/Gapagapi1/Cube-World-Alpha-Mods/releases) page to download the mods (built automatically from tags using Github workflows).

For a technical overview on what the mods do and how they achieve it, see the comments in the `.c` files.


## Server

### Mods

- **ServerConfig.dll**
  - uses `seed.cfg` instead of `server.cfg`
  - adds `port.cfg` to configure the listening port and falls back to port `12345` if `port.cfg` is missing or invalid

- **ServerGracefulShutdown.dll**
  - keeps the normal manual shutdown with `q`
  - also allows clean shutdown by creating a `shutdown.request` file

### Runtime files

- `seed.cfg` — world seed override
- `port.cfg` — port override
- `shutdown.request` — one-shot clean shutdown trigger

### Use

Place the DLLs in the `Server_Mods` folder used by the mod loader.

```text
Server_Mods/
  ServerConfig.dll
  ServerGracefulShutdown.dll
  ...
````


## Client

### Mods

- **ClientConfig.dll**
  - adds `port.cfg` to configure the listening port and falls back to port `12345` if `port.cfg` is missing or invalid

### Runtime files

- `port.cfg` — port override

### Use

Place the DLLs in the `Mods` folder used by the mod loader.

```text
Mods/
  ClientConfig.dll
  ...
````


## Build

Build as 32-bit Windows DLLs with MinGW-w64 MINGW32.

```bash
# See this script for compiling specific server mods
./server/compile_all.sh
```

```bash
# See this script for compiling specific client mods
./client/compile_all.sh
```
