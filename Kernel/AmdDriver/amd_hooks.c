#include <ntddk.h>
#include <ntstrsafe.h>
#include "amd_spoofer_ioctl.h"

// Глобальные переменные для хуков
extern WCHAR g_BiosSerial[MAX_SERIAL_LEN];
extern WCHAR g_SystemUUID[MAX_SERIAL_LEN];
extern WCHAR g_CpuId[MAX_SERIAL_LEN];
extern WCHAR g_MacAddress[MAX_SERIAL_LEN];
extern WCHAR g_MachineGuid[MAX_SERIAL_LEN];
extern WCHAR g_ProductId[MAX_SERIAL_LEN];
extern WCHAR g_HardwareId[MAX_HARDWARE_ID_LEN];
extern ULONG g_CpuFeatures;
extern ULONG64 g_CpuFrequency;

// Оригинальные функции
extern PVOID g_OriginalWmiQuery;
extern PVOID g_OriginalSmbiosQuery;
extern PVOID g_OriginalRegistryQuery;
extern PVOID g_OriginalNtQuerySystemInformation;
extern PVOID g_OriginalNtQueryInformationProcess;

// Флаги хуков
extern BOOLEAN g_WmiHooksInstalled;
extern BOOLEAN g_SmbiosHooksInstalled;
extern BOOLEAN g_RegistryHooksInstalled;

// Структуры для хуков
typedef struct _HOOK_DATA {
    PVOID OriginalFunction;
    PVOID HookFunction;
    UCHAR OriginalBytes[16];
    UCHAR HookBytes[16];
} HOOK_DATA, *PHOOK_DATA;

HOOK_DATA g_WmiHook = {0};
HOOK_DATA g_SmbiosHook = {0};
HOOK_DATA g_RegistryHook = {0};
HOOK_DATA g_SystemInfoHook = {0};
HOOK_DATA g_ProcessInfoHook = {0};

// Функции для установки хуков
NTSTATUS InstallWmiHooks(VOID)
{
    // Поиск WMI функции
    UNICODE_STRING wmiDeviceName;
    RtlInitUnicodeString(&wmiDeviceName, L"\\Device\\WmiGuid");
    
    PFILE_OBJECT fileObject;
    PDEVICE_OBJECT deviceObject;
    NTSTATUS status = IoGetDeviceObjectPointer(&wmiDeviceName, FILE_READ_DATA, &fileObject, &deviceObject);
    
    if (NT_SUCCESS(status)) {
        // Сохранение оригинальной функции
        g_WmiHook.OriginalFunction = deviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        g_WmiHook.HookFunction = HookWmiQuery;
        
        // Установка хука
        RtlCopyMemory(g_WmiHook.OriginalBytes, g_WmiHook.OriginalFunction, sizeof(g_WmiHook.OriginalBytes));
        RtlCopyMemory(g_WmiHook.HookBytes, &g_WmiHook.HookFunction, sizeof(PVOID));
        
        // Применение хука
        __try {
            RtlCopyMemory(g_WmiHook.OriginalFunction, g_WmiHook.HookBytes, sizeof(PVOID));
            g_WmiHooksInstalled = TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
        
        ObDereferenceObject(fileObject);
    }
    
    return status;
}

NTSTATUS InstallSmbiosHooks(VOID)
{
    // Поиск SMBIOS функции
    UNICODE_STRING smbiosDeviceName;
    RtlInitUnicodeString(&smbiosDeviceName, L"\\Device\\Smbios");
    
    PFILE_OBJECT fileObject;
    PDEVICE_OBJECT deviceObject;
    NTSTATUS status = IoGetDeviceObjectPointer(&smbiosDeviceName, FILE_READ_DATA, &fileObject, &deviceObject);
    
    if (NT_SUCCESS(status)) {
        // Сохранение оригинальной функции
        g_SmbiosHook.OriginalFunction = deviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        g_SmbiosHook.HookFunction = HookSmbiosQuery;
        
        // Установка хука
        RtlCopyMemory(g_SmbiosHook.OriginalBytes, g_SmbiosHook.OriginalFunction, sizeof(g_SmbiosHook.OriginalBytes));
        RtlCopyMemory(g_SmbiosHook.HookBytes, &g_SmbiosHook.HookFunction, sizeof(PVOID));
        
        // Применение хука
        __try {
            RtlCopyMemory(g_SmbiosHook.OriginalFunction, g_SmbiosHook.HookBytes, sizeof(PVOID));
            g_SmbiosHooksInstalled = TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
        
        ObDereferenceObject(fileObject);
    }
    
    return status;
}

NTSTATUS InstallRegistryHooks(VOID)
{
    // Хук на NtQueryValueKey
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"NtQueryValueKey");
    
    g_RegistryHook.OriginalFunction = MmGetSystemRoutineAddress(&functionName);
    if (g_RegistryHook.OriginalFunction) {
        g_RegistryHook.HookFunction = HookRegistryQuery;
        
        // Установка хука
        RtlCopyMemory(g_RegistryHook.OriginalBytes, g_RegistryHook.OriginalFunction, sizeof(g_RegistryHook.OriginalBytes));
        RtlCopyMemory(g_RegistryHook.HookBytes, &g_RegistryHook.HookFunction, sizeof(PVOID));
        
        // Применение хука
        __try {
            RtlCopyMemory(g_RegistryHook.OriginalFunction, g_RegistryHook.HookBytes, sizeof(PVOID));
            g_RegistryHooksInstalled = TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS InstallSystemInformationHooks(VOID)
{
    // Хук на NtQuerySystemInformation
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"NtQuerySystemInformation");
    
    g_SystemInfoHook.OriginalFunction = MmGetSystemRoutineAddress(&functionName);
    if (g_SystemInfoHook.OriginalFunction) {
        g_SystemInfoHook.HookFunction = HookNtQuerySystemInformation;
        
        // Установка хука
        RtlCopyMemory(g_SystemInfoHook.OriginalBytes, g_SystemInfoHook.OriginalFunction, sizeof(g_SystemInfoHook.OriginalBytes));
        RtlCopyMemory(g_SystemInfoHook.HookBytes, &g_SystemInfoHook.HookFunction, sizeof(PVOID));
        
        // Применение хука
        __try {
            RtlCopyMemory(g_SystemInfoHook.OriginalFunction, g_SystemInfoHook.HookBytes, sizeof(PVOID));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS InstallProcessInformationHooks(VOID)
{
    // Хук на NtQueryInformationProcess
    UNICODE_STRING functionName;
    RtlInitUnicodeString(&functionName, L"NtQueryInformationProcess");
    
    g_ProcessInfoHook.OriginalFunction = MmGetSystemRoutineAddress(&functionName);
    if (g_ProcessInfoHook.OriginalFunction) {
        g_ProcessInfoHook.HookFunction = HookNtQueryInformationProcess;
        
        // Установка хука
        RtlCopyMemory(g_ProcessInfoHook.OriginalBytes, g_ProcessInfoHook.OriginalFunction, sizeof(g_ProcessInfoHook.OriginalBytes));
        RtlCopyMemory(g_ProcessInfoHook.HookBytes, &g_ProcessInfoHook.HookFunction, sizeof(PVOID));
        
        // Применение хука
        __try {
            RtlCopyMemory(g_ProcessInfoHook.OriginalFunction, g_ProcessInfoHook.HookBytes, sizeof(PVOID));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }
    
    return STATUS_SUCCESS;
}

// Функции для удаления хуков
VOID UninstallWmiHooks(VOID)
{
    if (g_WmiHooksInstalled && g_WmiHook.OriginalFunction) {
        __try {
            RtlCopyMemory(g_WmiHook.OriginalFunction, g_WmiHook.OriginalBytes, sizeof(g_WmiHook.OriginalBytes));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        g_WmiHooksInstalled = FALSE;
    }
}

VOID UninstallSmbiosHooks(VOID)
{
    if (g_SmbiosHooksInstalled && g_SmbiosHook.OriginalFunction) {
        __try {
            RtlCopyMemory(g_SmbiosHook.OriginalFunction, g_SmbiosHook.OriginalBytes, sizeof(g_SmbiosHook.OriginalBytes));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        g_SmbiosHooksInstalled = FALSE;
    }
}

VOID UninstallRegistryHooks(VOID)
{
    if (g_RegistryHooksInstalled && g_RegistryHook.OriginalFunction) {
        __try {
            RtlCopyMemory(g_RegistryHook.OriginalFunction, g_RegistryHook.OriginalBytes, sizeof(g_RegistryHook.OriginalBytes));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        g_RegistryHooksInstalled = FALSE;
    }
}

VOID UninstallSystemInformationHooks(VOID)
{
    if (g_SystemInfoHook.OriginalFunction) {
        __try {
            RtlCopyMemory(g_SystemInfoHook.OriginalFunction, g_SystemInfoHook.OriginalBytes, sizeof(g_SystemInfoHook.OriginalBytes));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
}

VOID UninstallProcessInformationHooks(VOID)
{
    if (g_ProcessInfoHook.OriginalFunction) {
        __try {
            RtlCopyMemory(g_ProcessInfoHook.OriginalFunction, g_ProcessInfoHook.OriginalBytes, sizeof(g_ProcessInfoHook.OriginalBytes));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
}

// Функции-хуки для перехвата запросов
NTSTATUS HookWmiQuery(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    
    // Проверяем тип WMI запроса
    if (stack->Parameters.DeviceIoControl.IoControlCode == 0x80001000) { // WMI_QUERY_GUID
        // Получаем данные запроса
        PWMI_QUERY_GUID_DATA queryData = (PWMI_QUERY_GUID_DATA)Irp->AssociatedIrp.SystemBuffer;
        
        // Проверяем GUID запроса
        if (RtlCompareMemory(&queryData->Guid, &GUID_BATTERY_INFORMATION, sizeof(GUID)) == sizeof(GUID)) {
            // Возвращаем спуфированные данные батареи
            GenerateSpoofedBiosSerial((PWCHAR)queryData->Buffer, queryData->BufferSize);
            Irp->IoStatus.Information = sizeof(WCHAR) * MAX_SERIAL_LEN;
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
        else if (RtlCompareMemory(&queryData->Guid, &GUID_BIOS_INFORMATION, sizeof(GUID)) == sizeof(GUID)) {
            // Возвращаем спуфированные данные BIOS
            GenerateSpoofedBiosSerial((PWCHAR)queryData->Buffer, queryData->BufferSize);
            Irp->IoStatus.Information = sizeof(WCHAR) * MAX_SERIAL_LEN;
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
    }
    
    // Вызываем оригинальную функцию
    typedef NTSTATUS(*ORIGINAL_WMI_FUNC)(PDEVICE_OBJECT, PIRP);
    ORIGINAL_WMI_FUNC originalFunc = (ORIGINAL_WMI_FUNC)g_WmiHook.OriginalFunction;
    return originalFunc(DeviceObject, Irp);
}

NTSTATUS HookSmbiosQuery(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    
    // Проверяем тип SMBIOS запроса
    if (stack->Parameters.DeviceIoControl.IoControlCode == 0x80002000) { // SMBIOS_QUERY_TABLE
        // Получаем данные запроса
        PSMBIOS_QUERY_DATA queryData = (PSMBIOS_QUERY_DATA)Irp->AssociatedIrp.SystemBuffer;
        
        // Проверяем тип SMBIOS таблицы
        switch (queryData->TableType) {
            case 1: // BIOS Information
                GenerateSpoofedBiosSerial((PWCHAR)queryData->Buffer, queryData->BufferSize);
                break;
            case 2: // System Information
                GenerateSpoofedSystemUUID((PWCHAR)queryData->Buffer, queryData->BufferSize);
                break;
            case 4: // Processor Information
                GenerateSpoofedCpuId((PWCHAR)queryData->Buffer, queryData->BufferSize);
                break;
            default:
                // Для других типов возвращаем оригинальные данные
                break;
        }
        
        Irp->IoStatus.Information = queryData->BufferSize;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
    
    // Вызываем оригинальную функцию
    typedef NTSTATUS(*ORIGINAL_SMBIOS_FUNC)(PDEVICE_OBJECT, PIRP);
    ORIGINAL_SMBIOS_FUNC originalFunc = (ORIGINAL_SMBIOS_FUNC)g_SmbiosHook.OriginalFunction;
    return originalFunc(DeviceObject, Irp);
}

NTSTATUS HookRegistryQuery(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    
    // Проверяем тип Registry запроса
    if (stack->MajorFunction == IRP_MJ_QUERY_INFORMATION) {
        // Получаем имя ключа
        PUNICODE_STRING keyName = (PUNICODE_STRING)stack->Parameters.QueryFile.FileInformation;
        
        // Проверяем ключи, которые нужно спуфировать
        if (RtlCompareMemory(keyName->Buffer, L"BIOS", 8) == 8) {
            // Возвращаем спуфированные данные BIOS
            GenerateSpoofedBiosSerial((PWCHAR)Irp->AssociatedIrp.SystemBuffer, Irp->IoStatus.Information);
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
        else if (RtlCompareMemory(keyName->Buffer, L"SystemUUID", 20) == 20) {
            // Возвращаем спуфированные данные System UUID
            GenerateSpoofedSystemUUID((PWCHAR)Irp->AssociatedIrp.SystemBuffer, Irp->IoStatus.Information);
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
        }
    }
    
    // Вызываем оригинальную функцию
    typedef NTSTATUS(*ORIGINAL_REGISTRY_FUNC)(PDEVICE_OBJECT, PIRP);
    ORIGINAL_REGISTRY_FUNC originalFunc = (ORIGINAL_REGISTRY_FUNC)g_RegistryHook.OriginalFunction;
    return originalFunc(DeviceObject, Irp);
}

NTSTATUS HookNtQuerySystemInformation(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    
    // Получаем параметры запроса
    PSYSTEM_INFORMATION_CLASS infoClass = (PSYSTEM_INFORMATION_CLASS)stack->Parameters.DeviceIoControl.Type3InputBuffer;
    
    // Проверяем тип запроса
    switch (*infoClass) {
        case SystemBiosVersion:
            GenerateSpoofedBiosSerial((PWCHAR)Irp->AssociatedIrp.SystemBuffer, Irp->IoStatus.Information);
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
            
        case SystemFirmwareTableInformation:
            // Спуфируем SMBIOS таблицы
            GenerateSpoofedSystemUUID((PWCHAR)Irp->AssociatedIrp.SystemBuffer, Irp->IoStatus.Information);
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
            
        default:
            break;
    }
    
    // Вызываем оригинальную функцию
    typedef NTSTATUS(*ORIGINAL_SYSTEM_INFO_FUNC)(PDEVICE_OBJECT, PIRP);
    ORIGINAL_SYSTEM_INFO_FUNC originalFunc = (ORIGINAL_SYSTEM_INFO_FUNC)g_SystemInfoHook.OriginalFunction;
    return originalFunc(DeviceObject, Irp);
}

NTSTATUS HookNtQueryInformationProcess(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    
    // Получаем параметры запроса
    PPROCESSINFOCLASS infoClass = (PPROCESSINFOCLASS)stack->Parameters.DeviceIoControl.Type3InputBuffer;
    
    // Проверяем тип запроса
    switch (*infoClass) {
        case ProcessBasicInformation:
            // Скрываем информацию о процессе
            RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer, Irp->IoStatus.Information);
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
            
        case ProcessModuleInformation:
            // Скрываем информацию о модулях
            RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer, Irp->IoStatus.Information);
            Irp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_SUCCESS;
            
        default:
            break;
    }
    
    // Вызываем оригинальную функцию
    typedef NTSTATUS(*ORIGINAL_PROCESS_INFO_FUNC)(PDEVICE_OBJECT, PIRP);
    ORIGINAL_PROCESS_INFO_FUNC originalFunc = (ORIGINAL_PROCESS_INFO_FUNC)g_ProcessInfoHook.OriginalFunction;
    return originalFunc(DeviceObject, Irp);
}

// Функции для генерации спуфированных данных
VOID GenerateSpoofedBiosSerial(PWCHAR Buffer, ULONG BufferSize)
{
    if (wcslen(g_BiosSerial) > 0) {
        RtlCopyMemory(Buffer, g_BiosSerial, min(BufferSize, sizeof(g_BiosSerial)));
    } else {
        LARGE_INTEGER tickCount = KeQueryTickCount(NULL);
        RtlStringCchPrintfW(Buffer, BufferSize / sizeof(WCHAR), L"BIOS-%08X", tickCount.LowPart);
    }
}

VOID GenerateSpoofedSystemUUID(PWCHAR Buffer, ULONG BufferSize)
{
    if (wcslen(g_SystemUUID) > 0) {
        RtlCopyMemory(Buffer, g_SystemUUID, min(BufferSize, sizeof(g_SystemUUID)));
    } else {
        LARGE_INTEGER tickCount = KeQueryTickCount(NULL);
        RtlStringCchPrintfW(Buffer, BufferSize / sizeof(WCHAR), 
                           L"%08X-%04X-%04X-%04X-%08X%04X",
                           tickCount.LowPart,
                           (USHORT)(tickCount.HighPart & 0xFFFF),
                           (USHORT)((tickCount.HighPart >> 16) & 0xFFFF),
                           (USHORT)(tickCount.LowPart & 0xFFFF),
                           tickCount.LowPart,
                           (USHORT)(tickCount.HighPart & 0xFFFF));
    }
}

VOID GenerateSpoofedCpuId(PWCHAR Buffer, ULONG BufferSize)
{
    if (wcslen(g_CpuId) > 0) {
        RtlCopyMemory(Buffer, g_CpuId, min(BufferSize, sizeof(g_CpuId)));
    } else {
        LARGE_INTEGER tickCount = KeQueryTickCount(NULL);
        RtlStringCchPrintfW(Buffer, BufferSize / sizeof(WCHAR), L"CPU-%08X", tickCount.LowPart);
    }
}

VOID GenerateSpoofedMacAddress(PWCHAR Buffer, ULONG BufferSize)
{
    if (wcslen(g_MacAddress) > 0) {
        RtlCopyMemory(Buffer, g_MacAddress, min(BufferSize, sizeof(g_MacAddress)));
    } else {
        LARGE_INTEGER tickCount = KeQueryTickCount(NULL);
        RtlStringCchPrintfW(Buffer, BufferSize / sizeof(WCHAR), 
                           L"%02X:%02X:%02X:%02X:%02X:%02X",
                           (UCHAR)(tickCount.LowPart & 0xFF),
                           (UCHAR)((tickCount.LowPart >> 8) & 0xFF),
                           (UCHAR)((tickCount.LowPart >> 16) & 0xFF),
                           (UCHAR)((tickCount.LowPart >> 24) & 0xFF),
                           (UCHAR)(tickCount.HighPart & 0xFF),
                           (UCHAR)((tickCount.HighPart >> 8) & 0xFF));
    }
}

// Функции для проверки и валидации спуфированных данных
BOOLEAN IsValidSpoofedData(PWCHAR Data)
{
    if (!Data || wcslen(Data) == 0) {
        return FALSE;
    }
    
    for (ULONG i = 0; i < wcslen(Data); i++) {
        if (Data[i] < 32 || Data[i] > 126) {
            return FALSE;
        }
    }
    
    return TRUE;
}

// Функции для шифрования/дешифрования данных
VOID EncryptSpoofedData(PWCHAR Data, ULONG DataSize, PWCHAR Key)
{
    ULONG keyLength = wcslen(Key);
    for (ULONG i = 0; i < DataSize / sizeof(WCHAR); i++) {
        Data[i] ^= Key[i % keyLength];
    }
}

VOID DecryptSpoofedData(PWCHAR Data, ULONG DataSize, PWCHAR Key)
{
    EncryptSpoofedData(Data, DataSize, Key);
}

// Структуры для WMI и SMBIOS
typedef struct _WMI_QUERY_GUID_DATA {
    GUID Guid;
    ULONG BufferSize;
    PVOID Buffer;
} WMI_QUERY_GUID_DATA, *PWMI_QUERY_GUID_DATA;

typedef struct _SMBIOS_QUERY_DATA {
    ULONG TableType;
    ULONG BufferSize;
    PVOID Buffer;
} SMBIOS_QUERY_DATA, *PSMBIOS_QUERY_DATA;

// GUID для WMI запросов
GUID GUID_BATTERY_INFORMATION = {0x72631e54, 0x78a4, 0x11d0, {0xbc, 0xf7, 0x00, 0xaa, 0x00, 0xb7, 0xb3, 0x3a}};
GUID GUID_BIOS_INFORMATION = {0x9a7b6425, 0xcb90, 0x11d2, {0x8f, 0xfd, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b}}; 