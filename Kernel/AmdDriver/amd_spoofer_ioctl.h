#pragma once

#include <windows.h>

// IOCTL коды для AMD драйвера
#define IOCTL_AMD_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AMD_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AMD_SPOOF_SERIALS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AMD_HIDE_DRIVER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AMD_CLEAN_TRACES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AMD_INSTALL_HOOKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AMD_UNINSTALL_HOOKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AMD_GET_SPOOFED_DATA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AMD_BYPASS_ANTICHEAT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AMD_SPOOF_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Структуры для AMD драйвера
typedef struct _AMD_READ_MEMORY {
    ULONG64 Address;
    PVOID Buffer;
    ULONG Size;
} AMD_READ_MEMORY, *PAMD_READ_MEMORY;

typedef struct _AMD_WRITE_MEMORY {
    ULONG64 Address;
    PVOID Buffer;
    ULONG Size;
} AMD_WRITE_MEMORY, *PAMD_WRITE_MEMORY;

typedef struct _AMD_SPOOF_SERIALS {
    WCHAR BiosSerial[128];
    WCHAR BaseboardSerial[128];
    WCHAR SystemUUID[128];
    WCHAR DiskSerial[128];
    WCHAR CpuId[128];
    WCHAR MacAddress[128];
    WCHAR MachineGuid[128];
    WCHAR ProductId[128];
    WCHAR HardwareId[256];
    ULONG CpuFeatures;
    ULONG64 CpuFrequency;
    BOOLEAN EnableWmiHooks;
    BOOLEAN EnableSmbiosHooks;
    BOOLEAN EnableRegistryHooks;
    BOOLEAN EnableAntiCheatBypass;
} AMD_SPOOF_SERIALS, *PAMD_SPOOF_SERIALS;

typedef struct _AMD_HIDE_DRIVER {
    BOOLEAN HideFromPsLoadedModuleList;
    BOOLEAN CleanMmUnloadedDrivers;
    BOOLEAN CleanPiDDBCacheTable;
    BOOLEAN RemoveRegistryTraces;
    BOOLEAN SelfDeleteFile;
    BOOLEAN HideFromDriverList;
} AMD_HIDE_DRIVER, *PAMD_HIDE_DRIVER;

typedef struct _AMD_CLEAN_TRACES {
    BOOLEAN CleanEventLogs;
    BOOLEAN CleanPrefetch;
    BOOLEAN CleanTempFiles;
    BOOLEAN CleanRecentFiles;
    BOOLEAN CleanRegistryRunKeys;
    BOOLEAN CleanCrashDumps;
} AMD_CLEAN_TRACES, *PAMD_CLEAN_TRACES;

typedef struct _AMD_INSTALL_HOOKS {
    BOOLEAN HookWmiQuery;
    BOOLEAN HookSmbiosQuery;
    BOOLEAN HookRegistryQuery;
    BOOLEAN HookNtQuerySystemInformation;
    BOOLEAN HookNtQueryInformationProcess;
    BOOLEAN HookNtQueryInformationThread;
    BOOLEAN HookNtQueryInformationFile;
} AMD_INSTALL_HOOKS, *PAMD_INSTALL_HOOKS;

typedef struct _AMD_UNINSTALL_HOOKS {
    BOOLEAN UninstallAllHooks;
} AMD_UNINSTALL_HOOKS, *PAMD_UNINSTALL_HOOKS;

typedef struct _AMD_GET_SPOOFED_DATA {
    WCHAR RequestedData[128];
    WCHAR SpoofedValue[256];
    BOOLEAN Success;
} AMD_GET_SPOOFED_DATA, *PAMD_GET_SPOOFED_DATA;

typedef struct _AMD_BYPASS_ANTICHEAT {
    BOOLEAN BypassBattlEye;
    BOOLEAN BypassEasyAntiCheat;
    BOOLEAN BypassVanguard;
    BOOLEAN BypassRicochet;
    BOOLEAN BypassFairFight;
    BOOLEAN HideFromProcessList;
    BOOLEAN HideFromModuleList;
    BOOLEAN FakeSystemCalls;
} AMD_BYPASS_ANTICHEAT, *PAMD_BYPASS_ANTICHEAT;

typedef struct _AMD_SPOOF_PROCESS {
    WCHAR ProcessName[64];
    WCHAR FakeProcessName[64];
    BOOLEAN HideProcess;
    BOOLEAN SpoofProcessId;
    ULONG FakeProcessId;
} AMD_SPOOF_PROCESS, *PAMD_SPOOF_PROCESS; 