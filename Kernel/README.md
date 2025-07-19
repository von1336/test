# Ultimate HWID Spoofer - Улучшенные Драйверы

## Обзор

Это улучшенная версия драйверов для HWID спуфинга с расширенными антидетект-функциями. Драйверы обеспечивают полную незаметность от античитов и систем мониторинга.

## Особенности

### Антидетект-Функции

#### AMD Драйвер (`amd_spoofer_driver.c`)
- **Скрытие из системы**: Удаление из PsLoadedModuleList
- **Очистка следов**: Удаление из MmUnloadedDrivers и PiDDBCacheTable
- **Самоудаление**: Автоматическое удаление файла драйвера
- **Маскировка**: Случайные имена устройств и символических ссылок
- **Очистка логов**: Удаление журналов событий и временных файлов

#### Intel Драйвер (`intel_spoofer_driver.c`)
- **Все функции AMD драйвера**
- **Обход античитов**: BattlEye, EasyAntiCheat, Vanguard, Ricochet, FairFight
- **Скрытие процессов**: Удаление из списка процессов
- **Скрытие модулей**: Удаление из списка модулей
- **Подделка системных вызовов**: Фальсификация системной информации

### WMI/SMBIOS Хуки

#### Поддерживаемые хуки:
- **WMI Query**: Перехват WMI запросов для возврата спуфированных данных
- **SMBIOS Query**: Перехват SMBIOS запросов
- **Registry Query**: Перехват запросов к реестру
- **NtQuerySystemInformation**: Перехват системных запросов информации
- **NtQueryInformationProcess**: Перехват запросов информации о процессах
- **NtQueryInformationThread**: Перехват запросов информации о потоках
- **NtQueryInformationFile**: Перехват запросов информации о файлах

### Спуфированные Данные

#### Поддерживаемые типы данных:
- BIOS Serial Number
- System UUID
- CPU ID
- MAC Address
- Machine GUID
- Product ID
- Hardware ID
- CPU Features
- CPU Frequency
- Disk Serial
- Baseboard Serial

### IOCTL Команды

#### AMD Драйвер:
```c
IOCTL_AMD_READ_MEMORY          // Чтение памяти
IOCTL_AMD_WRITE_MEMORY         // Запись в память
IOCTL_AMD_SPOOF_SERIALS        // Установка спуфированных значений
IOCTL_AMD_HIDE_DRIVER          // Скрытие драйвера
IOCTL_AMD_CLEAN_TRACES         // Очистка следов
IOCTL_AMD_INSTALL_HOOKS        // Установка хуков
IOCTL_AMD_UNINSTALL_HOOKS      // Удаление хуков
IOCTL_AMD_GET_SPOOFED_DATA     // Получение спуфированных данных
```

#### Intel Драйвер:
```c
IOCTL_INTEL_READ_MEMORY        // Чтение памяти
IOCTL_INTEL_WRITE_MEMORY       // Запись в память
IOCTL_INTEL_SPOOF_SERIALS      // Установка спуфированных значений
IOCTL_INTEL_HIDE_DRIVER        // Скрытие драйвера
IOCTL_INTEL_CLEAN_TRACES       // Очистка следов
IOCTL_INTEL_INSTALL_HOOKS      // Установка хуков
IOCTL_INTEL_UNINSTALL_HOOKS    // Удаление хуков
IOCTL_INTEL_GET_SPOOFED_DATA   // Получение спуфированных данных
IOCTL_INTEL_BYPASS_ANTICHEAT   // Обход античитов
```

## Структура Файлов

```
Kernel/
├── AmdDriver/
│   ├── amd_spoofer_driver.c      // Основной AMD драйвер
│   ├── amd_spoofer_ioctl.h       // Заголовочный файл AMD
│   └── amd_hooks.c               // WMI/SMBIOS хуки для AMD
├── IntelDriver/
│   ├── intel_spoofer_driver.c    // Основной Intel драйвер
│   ├── intel_spoofer_ioctl.h     // Заголовочный файл Intel
│   └── intel_hooks.c             // WMI/SMBIOS хуки для Intel
└── README.md                     // Этот файл
```

## Компиляция

### Требования:
- Windows Driver Kit (WDK) 10 или новее
- Visual Studio 2019/2022
- Windows 10/11 SDK

### Компиляция AMD драйвера:
```batch
cd AmdDriver
cl /c /I"%DDKROOT%\inc" amd_spoofer_driver.c amd_hooks.c
link /driver /out:amd_spoofer.sys amd_spoofer_driver.obj amd_hooks.obj
```

### Компиляция Intel драйвера:
```batch
cd IntelDriver
cl /c /I"%DDKROOT%\inc" intel_spoofer_driver.c intel_hooks.c
link /driver /out:intel_spoofer.sys intel_spoofer_driver.obj intel_hooks.obj
```

## Использование

### Установка драйвера:
```batch
sc create "System32" type= kernel start= demand binPath= "C:\path\to\driver.sys"
sc start "System32"
```

### Удаление драйвера:
```batch
sc stop "System32"
sc delete "System32"
```

## Антидетект-Функции

### 1. Скрытие из системы
- Удаление из PsLoadedModuleList
- Очистка имени драйвера
- Скрытие из списка драйверов

### 2. Очистка следов
- Удаление из MmUnloadedDrivers
- Очистка PiDDBCacheTable
- Удаление журналов событий
- Очистка временных файлов
- Удаление crash dumps

### 3. Обход античитов
- **BattlEye**: Скрытие драйвера и процессов
- **EasyAntiCheat**: Подделка системных вызовов
- **Vanguard**: Скрытие модулей и процессов
- **Ricochet**: Обход детекции
- **FairFight**: Скрытие от серверной проверки

### 4. WMI/SMBIOS Хуки
- Перехват WMI запросов
- Перехват SMBIOS запросов
- Перехват Registry запросов
- Возврат спуфированных данных

## Безопасность

### Шифрование данных
- XOR шифрование спуфированных данных
- Валидация входных данных
- Проверка целостности

### Маскировка
- Случайные имена устройств
- Невинные символические ссылки
- Скрытие от систем мониторинга

### Самоудаление
- Автоматическое удаление файла драйвера
- Очистка реестра
- Удаление всех следов

## Предупреждения

⚠️ **ВАЖНО**: Использование этого ПО может нарушать условия использования игр и сервисов. Используйте на свой страх и риск.

⚠️ **БЕЗОПАСНОСТЬ**: Драйверы работают на уровне ядра и могут повредить систему при неправильном использовании.

## Лицензия

Этот код предоставляется "как есть" без каких-либо гарантий. Автор не несет ответственности за любой ущерб, причиненный использованием этого ПО.

## Поддержка

Для вопросов и предложений создавайте issues в репозитории проекта. 