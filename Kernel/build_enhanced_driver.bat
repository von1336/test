@echo off
echo Enhanced HWID Spoofer Driver Builder v2.0
echo ===========================================

REM Проверка наличия Visual Studio
where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo Ошибка: Visual Studio не найден
    echo Установите Visual Studio с Windows SDK
    pause
    exit /b 1
)

REM Создание папки для сборки
if not exist "build" mkdir build
if not exist "output" mkdir output

echo [1/5] Компиляция Enhanced драйвера...
cl.exe /c /I"%SDK_INC_PATH%" /I"%DDK_INC_PATH%" ^
    /DDRIVER /DWIN32 /D_WINDOWS /D_AMD64_ ^
    /DWINVER=0x0A00 /D_WIN32_WINNT=0x0A00 ^
    hwid_kernel_driver_enhanced.c /Fo:build\hwid_enhanced.obj

if %errorlevel% neq 0 (
    echo Ошибка компиляции Enhanced драйвера
    pause
    exit /b 1
)

echo [2/5] Линковка Enhanced драйвера...
link.exe /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry ^
    /OUT:output\hwid_enhanced.sys ^
    build\hwid_enhanced.obj ^
    ntoskrnl.lib hal.lib wdf01000.lib

if %errorlevel% neq 0 (
    echo Ошибка линковки Enhanced драйвера
    pause
    exit /b 1
)

echo [3/5] Создание INF файла...
(
echo [Version]
echo Signature="$WINDOWS NT$"
echo Class=System
echo ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}
echo Provider=%%ManufacturerName%%
echo DriverVer=2.0.0.0
echo CatalogFile=hwid_enhanced.cat
echo.
echo [DestinationDirs]
echo DefaultDestDir = 13
echo.
echo [SourceDisksNames]
echo 1 = %DiskName%%,,,""
echo.
echo [SourceDisksFiles]
echo hwid_enhanced.sys = 1,,
echo.
echo [Manufacturer]
echo %%ManufacturerName%% = Standard,NT$ARCH$.10.0...16299
echo.
echo [Standard.NT$ARCH$.10.0...16299]
echo %%DeviceName%% = hwid_enhanced_Device, Root\hwid_enhanced
echo.
echo [hwid_enhanced_Device.NT]
echo CopyFiles=Drivers_Dir
echo.
echo [Drivers_Dir]
echo hwid_enhanced.sys
echo.
echo [hwid_enhanced_Device.NT.Services]
echo AddService = hwid_enhanced,%SPSVCINST_ASSOCSERVICE%, hwid_enhanced_Service_Inst
echo.
echo [hwid_enhanced_Service_Inst]
echo DisplayName    = %%ServiceName%%
echo ServiceType    = 1
echo StartType      = 3
echo ErrorControl   = 1
echo ServiceBinary  = %%13%%\hwid_enhanced.sys
echo.
echo [Strings]
echo SPSVCINST_ASSOCSERVICE= 0x00000020
echo ManufacturerName = "System Provider"
echo DeviceName = "Enhanced HWID Spoofer Device"
echo ServiceName = "Enhanced HWID Spoofer Service"
echo DiskName = "Enhanced HWID Spoofer Installation Disk"
) > output\hwid_enhanced.inf

echo [4/5] Создание установочного скрипта...
(
echo @echo off
echo echo Enhanced HWID Spoofer Driver Installer
echo echo =====================================
echo.
echo REM Проверка прав администратора
echo net session ^>nul 2^>^&1
echo if %%errorlevel%% neq 0 ^(
echo     echo Требуются права администратора
echo     pause
echo     exit /b 1
echo ^)
echo.
echo REM Установка драйвера
echo pnputil /add-driver hwid_enhanced.inf /install
echo.
echo REM Загрузка драйвера
echo sc create "EnhancedHWIDSpoofer" binPath= "System32\drivers\hwid_enhanced.sys" type= kernel
echo sc start "EnhancedHWIDSpoofer"
echo.
echo echo Драйвер успешно установлен
echo pause
) > output\install_enhanced.bat

echo [5/5] Создание файла README...
(
echo Enhanced HWID Spoofer Driver v2.0
echo ==================================
echo.
echo Улучшенная версия драйвера для спуфинга HWID с расширенными возможностями
echo обхода античитов и улучшенной безопасностью.
echo.
echo Файлы:
echo - hwid_enhanced.sys - Основной драйвер
echo - hwid_enhanced.inf - Файл установки
echo - install_enhanced.bat - Скрипт установки
echo.
echo Особенности:
echo - Улучшенная безопасность и обфускация
echo - Расширенный обход античитов
echo - Поддержка SMEP bypass
echo - Патчинг ядра
echo - Валидация всех входных данных
echo.
echo Использование:
echo 1. Запустите install_enhanced.bat от имени администратора
echo 2. Драйвер будет установлен и загружен автоматически
echo 3. Используйте пользовательское приложение для управления
echo.
echo ВНИМАНИЕ: Используйте только в тестовых целях!
) > output\README_ENHANCED.txt

echo.
echo ===========================================
echo Сборка завершена успешно!
echo Файлы созданы в папке: output\
echo ===========================================
echo.
echo Созданные файлы:
echo - hwid_enhanced.sys (Enhanced драйвер)
echo - hwid_enhanced.inf (Файл установки)
echo - install_enhanced.bat (Скрипт установки)
echo - README_ENHANCED.txt (Документация)
echo.
pause 