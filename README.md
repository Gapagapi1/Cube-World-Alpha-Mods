# Cube World Alpha Mods

DLL mods for **Cube World Alpha**, for both the **server** and the **client**.

These mods are built for the original Alpha version and are intended to be used with the classic mod loaders:

- **Server mods** require the [Cube World Server Mod Launcher](https://github.com/coremaze/Cube-World-Server-Mod-Launcher)  
  Download: [prerelease2](https://github.com/coremaze/Cube-World-Server-Mod-Launcher/releases/tag/prerelease2)

- **Client mods** require the [Cube World Mod Launcher](https://github.com/coremaze/Cube-World-Mod-Launcher/tree/v1.5)  
  Download: [v1.5](https://github.com/coremaze/Cube-World-Mod-Launcher/releases/tag/v1.5)
  
  They should also work with later versions of this mod loader, such as [ToufouMaster/Cube-World-Mod-Launcher/tree/legacy](https://github.com/ToufouMaster/Cube-World-Mod-Launcher/tree/legacy)


You can download prebuilt binaries from the [Releases](https://github.com/Gapagapi1/Cube-World-Alpha-Mods/releases) page.  
Releases are built automatically from Git tags using GitHub Actions.

Debug DLLs are also included in releases. They are mainly useful for development and troubleshooting.

For a more technical explanation of how the mods work, see the comments in the `.c` source files.

---

## Server

### Mods

- **ServerConfig.dll**
  - uses `seed.cfg` instead of `server.cfg`
  - adds `port.cfg` to configure the listening port

- **ServerGracefulShutdown.dll**
  - keeps the original manual shutdown with `q`
  - also allows clean shutdown by creating a `shutdown.request` file

### Runtime files

- `seed.cfg` — world seed
- `port.cfg` — listening port
- `shutdown.request` — one-shot graceful shutdown trigger

### Installation

Place the server DLLs in the `Server_Mods` folder used by the server mod loader.

```text
Server_Mods/
  ServerConfig.dll
  ServerGracefulShutdown.dll
  ...
````

---

## Client

### Mods

- **ClientConfig.dll**

  - accepts `host:port` in the server connection field

### Installation

Place the client DLLs in the `Mods` folder used by the client mod loader.

```text
Mods/
  ClientConfig.dll
  ...
```

---

## Build

Build the DLLs as **32-bit Windows DLLs** with **MinGW-w64 MINGW32**.

```bash
# Build server mods
./server/compile_all.sh
```

```bash
# Build client mods
./client/compile_all.sh
```
