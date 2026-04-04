#define WIN32_LEAN_AND_MEAN
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <windows.h>
#include <winnt.h>
#include <winsock2.h>

/*
 * ============================================================================
 * Cube World Alpha - Client Config Mod
 * ============================================================================
 *
 * The goal of this mod is to make the Cube World Alpha client more
 * configurable.
 *
 *
 * What problem does this solve?
 * -----------------------------
 * The original client always connects to port 12345.
 *
 * This mod lets the existing server address field accept host, host:port,
 * ip or ip:port.
 *
 * Examples:
 *   192.168.1.21
 *   192.168.1.21:56184
 *   my-server.local
 *   my-server.local:56184
 *
 * If no port is specified, the client keeps the original default 12345 port.
 *
 * This mod works in pair with the Server Config Mod.
 *
 *
 * How does the mod work?
 * ----------------------
 * It uses two hooks:
 *
 *   1. Client connect routine hook
 *      We intercept it, inspect the existing address string,
 *      and if it contains ":port" we:
 *        - parse the port and save it globally
 *        - temporarily replace ':' with '\0'
 *            -> This is necessary because the original code passes the address
 *               string to inet_addr()/gethostbyname(), which would fail on
 *               "host:port".
 *        - call the original function from Cube.exe's code
 *        - restore the original string afterward with the ":port"
 *
 *   2. connect() IAT hook
 *      The client later builds sockaddr_in and always uses htons(12345).
 *      We intercept connect() and replace the destination port for the current
 *      connection attempt if the previous hook extracted an override.
 *
 * ============================================================================
 */

/*
 * Set this to TRUE for debugging. It will create a file called "ServerConfig.log"
 * where logs are appended. This behavior comes from the logf_line function below.
 */
#ifndef VERBOSE
#   define VERBOSE FALSE
#endif

/*
 * On 32-bit Windows, some functions use "__fastcall", which means the first
 * arguments are passed in CPU registers instead of only on the stack.
 *
 * Other member functions use "__thiscall", which is the usual calling
 * convention for non-static C++ methods on 32-bit Windows:
 *   - the "this" pointer is passed in ECX
 *   - the remaining arguments are passed on the stack
 *
 * We define these in a compiler-friendly way:
 *   - MSVC uses __fastcall / __thiscall
 *   - GCC (MinGW) uses __attribute__((fastcall)) / __attribute__((thiscall))
 */
#ifndef FASTCALL
#  if defined(_MSC_VER)
#    define FASTCALL __fastcall
#  else
#    define FASTCALL __attribute__((fastcall))
#  endif
#endif

#ifndef THISCALL
#  if defined(_MSC_VER)
#    define THISCALL __thiscall
#  else
#    define THISCALL __attribute__((thiscall))
#  endif
#endif


/*
 * These values came from Ghidra.
 *
 * IMAGE_BASE (documentation only):
 *   The base address where the executable expects to be loaded.
 *
 * CLIENT_CONNECT_RVA:
 *    RVA (Relative Virtual Address) of the original connect function itself,
 *    computed using IMAGE_BASE.
 */
#define IMAGE_BASE                  0x00400000u
#define CLIENT_CONNECT_RVA          0x0006FC50u


/*
 * Number of bytes stolen from the client connect routine for the hook.
 *
 * Here are the first 5 bytes of this function:
 *   55          push ebp
 *   8B EC       mov ebp, esp
 *   6A FF       push -1
 *
 * We replace them with a JMP to our hook.
 */
#define CLIENT_CONNECT_STOLEN_LEN   5


/*
 * The function pointer types for the original callables.
 *
 * We store it because after patching, we still want to be able to call
 * the original functions.
 */
typedef void (THISCALL *ClientConnectFn)(void *self, char *param_1);
typedef int (WSAAPI *ConnectFn)(SOCKET, const struct sockaddr *, int);

/* Global variable that will hold the original function pointers */
static ClientConnectFn g_original_client_connect = NULL;
static ConnectFn g_real_connect = NULL;


/*
 * One-shot connect override.
 *
 * This is scoped to the current thread so random connect() calls from other
 * threads are not accidentally patched.
 */
static volatile LONG g_override_active = 0;
static volatile DWORD g_override_thread_id = 0;
static volatile unsigned short g_override_port = 0;


/* Structure for parsing the "host:port" string */
typedef struct HostPatch {
    char *colon_ptr;
    int active;
} HostPatch;


/* This simply prints messages to a log file if the VERBOSE macro is set to TRUE. */
static void logf_line(const char *fmt, ...) {
    if (!VERBOSE) {
        return;
    }

    char buf[1024];
    va_list ap;

    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (len < 0) {
        return;
    }
    if ((size_t)len >= sizeof(buf)) {
        len = (int)(sizeof(buf) - 1);
    }

    HANDLE h = CreateFileA(
        "ClientConfig.log",
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (h == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD written;
    WriteFile(h, buf, (DWORD)len, &written, NULL);
    WriteFile(h, "\r\n", 2, &written, NULL);
    CloseHandle(h);
}


/* Case-insensitive ASCII string compare. */
static int streqi_ascii(const char *a, const char *b) {
    for (;;) {
        char ca = *a++;
        char cb = *b++;

        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb - 'A' + 'a');

        if (ca != cb)
            return 0;
        if (ca == '\0')
            return 1;
    }
}


/*
 * Network protocols store port numbers in "network byte order" (big-endian).
 *
 * Normal x86 CPUs use little-endian, so a value like 12345 must be byte-swapped
 * before being placed into sockaddr_in.sin_port.
 *
 * This function does the same job as htons(), but manually.
 */
static unsigned short to_network_u16(unsigned short value) {
    return (unsigned short)(((value & 0x00FFu) << 8) |
                            ((value & 0xFF00u) >> 8));
}


/* Helper for setting the thread specific global port save. */
static void set_override_port(unsigned short port) {
    g_override_port = port;
    g_override_thread_id = GetCurrentThreadId();
    InterlockedExchange(&g_override_active, 1);
}

/* Helper for clearing the thread specific global port save. */
static void clear_override_port(void) {
    InterlockedExchange(&g_override_active, 0);
    g_override_thread_id = 0;
    g_override_port = 0;
}


/*
 * Helper for handling the user string.
 *
 * It reproduced the following reverse-engineered behavior from the connect routine.
 *
 * If capacity > 0xF, the char* is heap-allocated at offset +0 otherwise the
 * bytes are inline in the object itself. Here are the offsets:
 *   +0x10 = size
 *   +0x14 = capacity
 */
static char *client_string_cstr(char *str_obj) {
    uint32_t capacity = *(uint32_t *)(str_obj + 0x14);

    if (capacity > 0x0F) {
        return *(char **)str_obj;
    }
    return str_obj;
}


/* Parse the port from the user string, atoi-style */
static int parse_decimal_port(const char *string, unsigned short *out_port) {
    unsigned long value = 0;

    if (string == NULL || *string == '\0') {
        return 0;
    }

    const unsigned char *ptr = (const unsigned char *)string;

    while (*ptr != '\0') {
        if (!isdigit(*ptr)) {
            return 0;
        }
        value = value * 10 + (unsigned long)(*ptr - '0');
        if (value > 65535UL) {
            return 0;
        }
        ++ptr;
    }

    if (value == 0 || value > 65535UL) {
        return 0;
    }

    *out_port = (unsigned short)value;
    return 1;
}


/*
 * This parses "host:port" from the existing menu string.
 *
 * This intentionally does not try to support IPv6, because the original client
 * code is clearly IPv4-oriented (inet_addr + gethostbyname + sockaddr_in).
 */
static int patch_host_string(char *param_1, unsigned short *out_port, HostPatch *patch) {
    patch->colon_ptr = NULL;
    patch->active = 0;

    if (param_1 == NULL) {
        return 0;
    }

    char *string = client_string_cstr(param_1);
    if (string == NULL || *string == '\0') {
        return 0;
    }

    char *colon = strrchr(string, ':');
    if (colon == NULL) {
        return 0;
    }

    if (colon == string) {
        return 0;
    }

    unsigned short port;
    if (!parse_decimal_port(colon + 1, &port)) {
        return 0;
    }

    patch->colon_ptr = colon;
    patch->active = 1;

    *colon = '\0';
    *out_port = port;

    logf_line("[cw-client-port] parsed host override: host=\"%s\" port=%u", string, (unsigned)port);

    return 1;
}

static void restore_host_patch(HostPatch *patch) {
    if (patch != NULL && patch->active && patch->colon_ptr != NULL) {
        *patch->colon_ptr = ':';
        patch->active = 0;
    }
}


/*
 * This function replaces the client's imported Winsock connect().
 *
 * This hook checks whether an override is active for the current thread.
 * If so, it makes a local writable copy of the sockaddr_in, replaces sin_port,
 * and then calls the real connect() with the patched address.
 *
 * The override is meant for the one connection attempt triggered by the current
 * menu action. Restricting it to the current thread reduces the chance of
 * accidentally affecting another connect() call elsewhere in the client.
 */
static int WSAAPI hooked_connect(SOCKET s, const struct sockaddr *name, int namelen) {
    if (g_real_connect == NULL) {
        logf_line("[cw-client-port] g_real_connect is NULL");
        return SOCKET_ERROR;
    }

    /*
     * Only patch the address if all of the following are true:
     *   1. A port override is currently active
     *   2. That override belongs to this thread
     *   3. The sockaddr pointer is valid
     *   4. The structure is large enough to be a sockaddr_in
     *   5. The address family is IPv4
     *
     * We use InterlockedCompareExchange(..., 0, 0) as an atomic read of the
     * "active" flag without changing it.
     */
    if (InterlockedCompareExchange(&g_override_active, 0, 0)
        && g_override_thread_id == GetCurrentThreadId()
        && name != NULL
        && namelen >= (int)sizeof(struct sockaddr_in)
        && name->sa_family == AF_INET) {

        /* Make a local writable copy of the original IPv4 socket address. */
        struct sockaddr_in patched = *(const struct sockaddr_in *)name;

        /*
         * Replace the destination port with the parsed override port.
         * As in the Server Config Mod, sin_port must be stored in network byte order.
         */
        patched.sin_port = to_network_u16(g_override_port);

        logf_line("[cw-client-port] overriding connect port -> %u", (unsigned)g_override_port);

        /* Forward the call to the real connect() */
        return g_real_connect(s, (const struct sockaddr *)&patched, namelen);
    }

    /* No override applies here, so just forward the call unchanged */
    return g_real_connect(s, name, namelen);
}

/*
 * This function patches the main executable's Import Address Table (IAT)
 * entry for connect().
 *
 * When a Windows executable imports a function from a DLL, Windows resolves
 * that function to a real address at load time and stores the resolved pointer
 * in the executable's Import Address Table.
 *
 * For example, if the client imports connect() from WS2_32.dll, the IAT holds
 * the function pointer that the client will actually call at runtime.
 *
 * If we replace the IAT entry for connect(), then when the server thinks it is
 * calling connect(), it actually calls our hooked_connect() first.
 *
 * Here are the steps performed here:
 *   1. Get the base address of the main executable
 *   2. Get a handle to WS2_32.dll
 *   3. Resolve the real connect() address
 *   4. Parse the PE headers of the main executable
 *   5. Walk its import table
 *   6. Find the IAT slot that points to the real connect()
 *   7. Replace that slot with hooked_connect
 *
 * For more details, please read the comments in the Server Config Mod's code,
 * the principle is exactly the same.
 */
static int patch_main_exe_iat_connect(void) {
    HMODULE main_module = GetModuleHandleA(NULL);
    if (!main_module) {
        logf_line("[cw-client-port] GetModuleHandleA(NULL) failed in IAT patch");
        return 0;
    }

    HMODULE ws2_module = GetModuleHandleA("WS2_32.dll");
    if (!ws2_module) {
        ws2_module = LoadLibraryA("WS2_32.dll");
    }
    if (!ws2_module) {
        logf_line("[cw-client-port] could not load WS2_32.dll");
        return 0;
    }

    FARPROC connect_addr = GetProcAddress(ws2_module, "connect");
    if (!connect_addr) {
        logf_line("[cw-client-port] GetProcAddress(connect) failed");
        return 0;
    }

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)main_module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        logf_line("[cw-client-port] DOS signature check failed");
        return 0;
    }

    IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)((BYTE *)main_module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        logf_line("[cw-client-port] NT signature check failed");
        return 0;
    }

    IMAGE_DATA_DIRECTORY import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) {
        logf_line("[cw-client-port] no import directory");
        return 0;
    }

    for (
        IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)main_module + import_dir.VirtualAddress);
        imp->Name != 0;
        ++imp
    ) {
        const char *dll_name = (const char *)((BYTE *)main_module + imp->Name);
        IMAGE_THUNK_DATA32 *iat_thunk;

        if (!streqi_ascii(dll_name, "WS2_32.dll") &&
            !streqi_ascii(dll_name, "wsock32.dll")) {
            continue;
        }

        for (
            iat_thunk = (IMAGE_THUNK_DATA32 *)((BYTE *)main_module + imp->FirstThunk);
            iat_thunk->u1.Function != 0;
            ++iat_thunk
        ) {
            void **slot = (void **)&iat_thunk->u1.Function;

            if ((FARPROC)(uintptr_t)iat_thunk->u1.Function != connect_addr) {
                continue;
            }

            g_real_connect = (ConnectFn)connect_addr;

            logf_line("[cw-client-port] connect IAT slot = %p", slot);
            logf_line("[cw-client-port] original connect = %p", connect_addr);

            DWORD old_protect = 0;
            if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &old_protect)) {
                logf_line("[cw-client-port] VirtualProtect failed for connect IAT slot");
                return 0;
            }

            *slot = (void *)&hooked_connect;

            VirtualProtect(slot, sizeof(*slot), old_protect, &old_protect);

            FlushInstructionCache(GetCurrentProcess(), slot, sizeof(*slot));

            logf_line("[cw-client-port] patched connect = %p", *slot);
            logf_line("[cw-client-port] connect IAT patched");

            return 1;
        }
    }

    logf_line("[cw-client-port] could not find connect in main executable IAT");
    return 0;
}

/*
 * Installs a 32-bit inline detour at the start of a function by writing
 * a JMP instruction to a replacement function.
 *
 * It also creates a trampoline so the original function can still be called.
 *
 * To install a 32-bit near JMP, we need 5 bytes: E9 xx xx xx xx
 * But we cannot overwrite arbitrary bytes. We must steal whole instructions
 * from the start of the original function. Those stolen bytes are copied into
 * the trampoline so execution can continue correctly.
 *
 * The trampoline is an executable memory used to save the instructions we
 * override. Here are the instructions it contains:
 *   [stolen original bytes]
 *   [jmp back to target + stolen_len]
 *
 * So calling the trampoline is effectively "call original function, but with
 * the first bytes replayed from another location".
 */
static int patch_with_jmp(void *target, void *replacement, size_t stolen_len, void **out_trampoline) {
    /*
     * A 32-bit near JMP rel32 requires exactly 5 bytes.
     * If we steal fewer than 5 bytes, we cannot install the detour.
     */
    if (stolen_len < 5) {
        return 0;
    }

    /*
     * Allocate executable memory for the trampoline of length
     * stolen bytes + 5-byte jump back to the original function
     */
    BYTE *tramp = (BYTE *)VirtualAlloc(NULL, stolen_len + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (tramp == NULL) {
        return 0;
    }

    BYTE *src = (BYTE *)target;

    /* Copy the stolen instructions from the original function into the trampoline. */
    memcpy(tramp, src, stolen_len);

    /*
     * Append a JMP from the trampoline back to the original function after
     * the stolen bytes.
     *
     * Here is the layout of a JMP:
     *   tramp[stolen_len + 0] = E9
     *   tramp[stolen_len + 1 ... 4] = relative destination
     */
    tramp[stolen_len] = 0xE9;
    intptr_t rel = ((BYTE *)src + stolen_len) - (tramp + stolen_len + 5);
    *(int32_t *)(tramp + stolen_len + 1) = (int32_t)rel;

    /* Make the beginning of the original function writable so we can patch it. */
    DWORD old_protect = 0;
    if (!VirtualProtect(src, stolen_len, PAGE_EXECUTE_READWRITE, &old_protect)) {
        VirtualFree(tramp, 0, MEM_RELEASE);
        return 0;
    }

    /* Overwrite the function entry with the JMP replacement */
    src[0] = 0xE9;
    rel = (BYTE *)replacement - (src + 5);
    *(int32_t *)(src + 1) = (int32_t)rel;

    /*
     * If we stole more than 5 bytes, fill the remaining overwritten region
     * with NOP instructions so the patched area stays clean.
     */
    if (stolen_len > 5) {
        memset(src + 5, 0x90, stolen_len - 5);
    }

    /* Restore the original page protection and flush instruction cache. */
    VirtualProtect(src, stolen_len, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), src, stolen_len);

    *out_trampoline = tramp;
    return 1;
}

/* This is the detour replacement for the client's connect routine. */
static void THISCALL hooked_client_connect(void *self, char *param_1) {
    HostPatch patch;
    unsigned short port = 0;

    /*
     * Try to parse "host:port" from the menu string.
     * If successful, activate a one-shot override for the upcoming connect().
     * If not, clear any stale override state.
     */
    if (patch_host_string(param_1, &port, &patch)) {
        set_override_port(port);
    } else {
        clear_override_port();
        patch.active = 0;
    }

    /*
     * Run the original client connect routine through the trampoline.
     * At this point the host string temporarily contain only "host"
     * instead of "host:port" if the override is active.
     */
    g_original_client_connect(self, param_1);

    /*
     * Restore the original menu string so the UI still shows exactly what the
     * user typed.
     */
    restore_host_patch(&patch);

    /*
     * Clear the override after the connect attempt.
     * This prevents accidental reuse by later connect() calls.
     */
    clear_override_port();
}

/*
 * Patches the client's connect routine with an inline JMP detour using patch_with_jmp
 * and update global state accordingly.
 */
static int patch_client_connect_function(void) {
    BYTE *base = (BYTE *)GetModuleHandleA(NULL);
    if (base == NULL) {
        logf_line("[cw-client-port] GetModuleHandleA(NULL) failed in function patch");
        return 0;
    }

    void *target = (void *)(base + CLIENT_CONNECT_RVA);

    logf_line("[cw-client-port] client connect target = %p", target);

    void *trampoline = NULL;
    if (!patch_with_jmp(target,
                        (void *)&hooked_client_connect,
                        CLIENT_CONNECT_STOLEN_LEN,
                        &trampoline)) {
        logf_line("[cw-client-port] patch_with_jmp failed");
        return 0;
    }

    g_original_client_connect = (ClientConnectFn)trampoline;

    logf_line("[cw-client-port] trampoline = %p", trampoline);
    logf_line("[cw-client-port] client connect detour patched");

    return 1;
}


/*
 * DllMain is a delicate place to run code.
 * Windows recommends doing as little as possible there.
 *
 * So in DllMain we only create a thread, and that thread does the real work.
 */
static DWORD WINAPI init_thread(LPVOID unused) {
    (void)unused;
    logf_line("[cw-client-port] init thread started");
    patch_client_connect_function();
    patch_main_exe_iat_connect();
    return 0;
}


/*
 * The modloader calls this automatically when the DLL is loaded.
 *
 * We disable useless thread attach/detach notifications and start our
 * init thread.
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    HANDLE thread;

    (void)lpReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);

        thread = CreateThread(NULL, 0, init_thread, NULL, 0, NULL);
        if (thread != NULL) {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
