@echo off
setlocal EnableDelayedExpansion

:: =============================================================================
:: Ping - Decentralized Encrypted Messenger
:: Windows Autoinstaller Script
::
:: Usage: install.cmd [OPTIONS]
::
:: Options:
::   --no-optional     Skip optional dependencies (secp256k1, coincurve, qrcode)
::   --no-git          Skip Git installation
::   --clone           Clone full repository instead of single file download
::   --help            Show this help message
::
:: Repository: https://github.com/attacless/ping
:: License: MIT
:: =============================================================================

:: Configuration
set "REPO_URL=https://github.com/attacless/ping.git"
set "RAW_URL=https://raw.githubusercontent.com/attacless/ping/main/ping.py"
set "SCRIPT_NAME=ping.py"
set "MIN_PYTHON_VERSION=3.12"

:: Default options
set "INSTALL_OPTIONAL=1"
set "INSTALL_GIT=1"
set "CLONE_REPO=0"

:: Parse arguments
:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="--no-optional" (
    set "INSTALL_OPTIONAL=0"
    shift
    goto :parse_args
)
if /i "%~1"=="--no-git" (
    set "INSTALL_GIT=0"
    shift
    goto :parse_args
)
if /i "%~1"=="--clone" (
    set "CLONE_REPO=1"
    shift
    goto :parse_args
)
if /i "%~1"=="--help" goto :show_help
if /i "%~1"=="-h" goto :show_help
echo [ERROR] Unknown option: %~1
goto :show_help
:args_done

:: Print banner
call :print_banner

:: Check for admin rights (informational only)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Running without administrator privileges.
    echo [INFO] If winget fails, try running as Administrator.
    echo.
)

:: Check for winget
echo [INFO] Checking for winget...
where winget >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] winget not found.
    echo [ERROR] Please install App Installer from the Microsoft Store or update Windows.
    echo [ERROR] Alternatively, install Python 3.12+ manually from https://python.org
    goto :error_exit
)
echo [OK] winget found

:: Check for existing Python installation
echo.
echo [INFO] Checking for Python %MIN_PYTHON_VERSION%+...
call :check_python
if %errorlevel% equ 0 (
    echo [OK] Found Python: !PYTHON_CMD! ^(!PYTHON_VERSION!^)
    goto :python_ready
)

:: Install Python
echo [WARN] Python %MIN_PYTHON_VERSION%+ not found. Installing...
echo.
winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install Python via winget.
    echo [ERROR] Please install Python 3.12+ manually from https://python.org
    goto :error_exit
)

:: Refresh PATH for current session
call :refresh_path

:: Verify Python installation
call :check_python
if %errorlevel% neq 0 (
    echo [ERROR] Python installation succeeded but python not found in PATH.
    echo [ERROR] Please close this window and run the installer again,
    echo [ERROR] or add Python to your PATH manually.
    goto :error_exit
)
echo [OK] Python installed: !PYTHON_CMD! ^(!PYTHON_VERSION!^)

:python_ready

:: Install Git if needed and requested
if "%CLONE_REPO%"=="1" (
    if "%INSTALL_GIT%"=="1" (
        echo.
        echo [INFO] Checking for Git...
        where git >nul 2>&1
        if %errorlevel% neq 0 (
            echo [WARN] Git not found. Installing...
            winget install -e --id Git.Git --accept-source-agreements --accept-package-agreements
            if %errorlevel% neq 0 (
                echo [ERROR] Failed to install Git.
                echo [ERROR] Install manually or run without --clone flag.
                goto :error_exit
            )
            call :refresh_path
        )
        where git >nul 2>&1
        if %errorlevel% neq 0 (
            echo [ERROR] Git installation succeeded but git not found in PATH.
            echo [ERROR] Please restart your terminal and try again.
            goto :error_exit
        )
        echo [OK] Git found
    )
)

:: Upgrade pip
echo.
echo [->] Upgrading pip...
!PYTHON_CMD! -m pip install -U pip --quiet
if %errorlevel% neq 0 (
    echo [WARN] Failed to upgrade pip, continuing with existing version...
)

:: Install required dependencies
echo.
echo [->] Installing required dependencies...
!PYTHON_CMD! -m pip install cryptography websockets certifi --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install required dependencies.
    goto :error_exit
)
echo [OK] Required dependencies installed

:: Install optional dependencies
if "%INSTALL_OPTIONAL%"=="1" (
    echo.
    echo [->] Installing optional dependencies...
    
    :: Try secp256k1 first (faster crypto)
    !PYTHON_CMD! -m pip install secp256k1 --quiet 2>nul
    if %errorlevel% neq 0 (
        echo [WARN] secp256k1 not available, trying coincurve...
        !PYTHON_CMD! -m pip install coincurve --quiet 2>nul
        if %errorlevel% neq 0 (
            echo [WARN] coincurve also unavailable ^(optional, will use slower fallback^)
        ) else (
            echo [OK] coincurve installed
        )
    ) else (
        echo [OK] secp256k1 installed
    )
    
    :: QR code generation
    !PYTHON_CMD! -m pip install qrcode --quiet 2>nul
    if %errorlevel% neq 0 (
        echo [WARN] qrcode unavailable ^(optional^)
    ) else (
        echo [OK] qrcode installed
    )
)

:: Download Ping
echo.
if "%CLONE_REPO%"=="1" (
    echo [->] Cloning repository...
    if exist "ping" (
        echo [WARN] Directory 'ping' already exists.
        set /p "OVERWRITE=Remove and re-clone? [y/N] "
        if /i "!OVERWRITE!"=="y" (
            rmdir /s /q ping
        ) else (
            echo [ERROR] Aborted.
            goto :error_exit
        )
    )
    git clone %REPO_URL%
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to clone repository.
        goto :error_exit
    )
    cd ping
    echo [OK] Repository cloned
) else (
    echo [->] Downloading %SCRIPT_NAME%...
    if exist "%SCRIPT_NAME%" (
        echo [WARN] %SCRIPT_NAME% already exists.
        set /p "OVERWRITE=Overwrite? [y/N] "
        if /i not "!OVERWRITE!"=="y" (
            echo [ERROR] Aborted.
            goto :error_exit
        )
    )
    
    :: Try curl first (built into Windows 10+)
    where curl.exe >nul 2>&1
    if %errorlevel% equ 0 (
        curl.exe -fsSL -o %SCRIPT_NAME% %RAW_URL%
        if %errorlevel% neq 0 (
            echo [ERROR] Failed to download %SCRIPT_NAME%
            goto :error_exit
        )
    ) else (
        :: Fall back to PowerShell
        echo [INFO] curl not found, using PowerShell...
        powershell -Command "Invoke-WebRequest -Uri '%RAW_URL%' -OutFile '%SCRIPT_NAME%'" 2>nul
        if %errorlevel% neq 0 (
            echo [ERROR] Failed to download %SCRIPT_NAME%
            goto :error_exit
        )
    )
    echo [OK] Downloaded %SCRIPT_NAME%
)

:: Verify installation
echo.
echo [->] Verifying installation...
call :verify_installation
if %errorlevel% neq 0 (
    echo [ERROR] Installation verification failed.
    goto :error_exit
)

:: Success
echo.
echo ============================================================
echo [OK] Installation complete!
echo ============================================================
echo.
echo To start Ping:
if "%CLONE_REPO%"=="1" (
    echo   cd ping ^&^& !PYTHON_CMD! ping.py
) else (
    echo   !PYTHON_CMD! ping.py
)
echo.
echo Quick commands:
echo   Generate new identity:  !PYTHON_CMD! ping.py --new
echo   Show your public key:   !PYTHON_CMD! ping.py --show-pubkey
echo   Show help:              !PYTHON_CMD! ping.py --help
echo.

:: Ask if user wants to run Ping now
set /p "RUN_NOW=Start Ping now? [Y/n] "
if /i not "!RUN_NOW!"=="n" (
    echo.
    echo [->] Starting Ping...
    echo.
    !PYTHON_CMD! ping.py
)

goto :eof

:: =============================================================================
:: Functions
:: =============================================================================

:print_banner
echo.
echo     ____  _            
echo    / __ \(_)___  ____ _
echo   / /_/ / / __ \/ __ `/
echo  / ____/ / / / / /_/ / 
echo /_/   /_/_/ /_/\__, /  
echo               /____/   
echo.
echo Decentralized Encrypted Messenger
echo Installer v1.0.0 ^(Windows^)
echo.
goto :eof

:show_help
echo.
echo Ping Autoinstaller for Windows
echo.
echo Usage: install.cmd [OPTIONS]
echo.
echo Options:
echo     --no-optional     Skip optional dependencies (secp256k1, coincurve, qrcode)
echo     --no-git          Skip Git installation
echo     --clone           Clone full repository instead of single file download
echo     --help            Show this help message
echo.
echo Examples:
echo     # Standard installation
echo     install.cmd
echo.
echo     # Minimal installation (required deps only)
echo     install.cmd --no-optional
echo.
echo     # Clone full repository
echo     install.cmd --clone
echo.
goto :eof

:check_python
:: Check for Python 3.12+ in various locations
set "PYTHON_CMD="
set "PYTHON_VERSION="

:: Try py launcher first (recommended on Windows)
where py >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=*" %%v in ('py -3.12 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2^>nul') do set "PYTHON_VERSION=%%v"
    if defined PYTHON_VERSION (
        set "PYTHON_CMD=py -3.12"
        exit /b 0
    )
    for /f "tokens=*" %%v in ('py -3.13 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2^>nul') do set "PYTHON_VERSION=%%v"
    if defined PYTHON_VERSION (
        set "PYTHON_CMD=py -3.13"
        exit /b 0
    )
    for /f "tokens=*" %%v in ('py -3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2^>nul') do set "PYTHON_VERSION=%%v"
    if defined PYTHON_VERSION (
        call :version_check !PYTHON_VERSION!
        if !errorlevel! equ 0 (
            set "PYTHON_CMD=py -3"
            exit /b 0
        )
    )
)

:: Try python directly
where python >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=*" %%v in ('python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2^>nul') do set "PYTHON_VERSION=%%v"
    if defined PYTHON_VERSION (
        call :version_check !PYTHON_VERSION!
        if !errorlevel! equ 0 (
            set "PYTHON_CMD=python"
            exit /b 0
        )
    )
)

:: Try python3
where python3 >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=*" %%v in ('python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2^>nul') do set "PYTHON_VERSION=%%v"
    if defined PYTHON_VERSION (
        call :version_check !PYTHON_VERSION!
        if !errorlevel! equ 0 (
            set "PYTHON_CMD=python3"
            exit /b 0
        )
    )
)

exit /b 1

:version_check
:: Check if version meets minimum requirement (3.12)
set "VER=%~1"
for /f "tokens=1,2 delims=." %%a in ("%VER%") do (
    set "MAJOR=%%a"
    set "MINOR=%%b"
)
if %MAJOR% gtr 3 exit /b 0
if %MAJOR% equ 3 if %MINOR% geq 12 exit /b 0
exit /b 1

:refresh_path
:: Attempt to refresh PATH without restarting terminal
echo [INFO] Refreshing PATH...

:: Get updated PATH from registry
for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "SYS_PATH=%%b"
for /f "tokens=2*" %%a in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "USER_PATH=%%b"

:: Combine paths
if defined SYS_PATH if defined USER_PATH (
    set "PATH=%SYS_PATH%;%USER_PATH%"
) else if defined SYS_PATH (
    set "PATH=%SYS_PATH%"
) else if defined USER_PATH (
    set "PATH=%USER_PATH%"
)

:: Also check common Python install locations
set "PATH=%PATH%;%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Programs\Python\Python312\Scripts"
set "PATH=%PATH%;%LOCALAPPDATA%\Programs\Python\Python313;%LOCALAPPDATA%\Programs\Python\Python313\Scripts"
set "PATH=%PATH%;%ProgramFiles%\Python312;%ProgramFiles%\Python312\Scripts"
set "PATH=%PATH%;%ProgramFiles%\Python313;%ProgramFiles%\Python313\Scripts"

goto :eof

:verify_installation
:: Verify required modules are installed
set "MISSING="

!PYTHON_CMD! -c "import cryptography" 2>nul
if %errorlevel% neq 0 set "MISSING=!MISSING! cryptography"

!PYTHON_CMD! -c "import websockets" 2>nul
if %errorlevel% neq 0 set "MISSING=!MISSING! websockets"

!PYTHON_CMD! -c "import certifi" 2>nul
if %errorlevel% neq 0 set "MISSING=!MISSING! certifi"

if defined MISSING (
    echo [ERROR] Missing required modules:!MISSING!
    exit /b 1
)

echo [OK] All required modules verified

:: Check optional modules
set "OPTIONAL_FOUND="
set "OPTIONAL_MISSING="

!PYTHON_CMD! -c "import secp256k1" 2>nul
if %errorlevel% equ 0 (
    set "OPTIONAL_FOUND=!OPTIONAL_FOUND! secp256k1"
) else (
    !PYTHON_CMD! -c "import coincurve" 2>nul
    if %errorlevel% equ 0 (
        set "OPTIONAL_FOUND=!OPTIONAL_FOUND! coincurve"
    ) else (
        set "OPTIONAL_MISSING=!OPTIONAL_MISSING! secp256k1/coincurve"
    )
)

!PYTHON_CMD! -c "import qrcode" 2>nul
if %errorlevel% equ 0 (
    set "OPTIONAL_FOUND=!OPTIONAL_FOUND! qrcode"
) else (
    set "OPTIONAL_MISSING=!OPTIONAL_MISSING! qrcode"
)

if defined OPTIONAL_FOUND echo [INFO] Optional modules installed:!OPTIONAL_FOUND!
if defined OPTIONAL_MISSING if "%INSTALL_OPTIONAL%"=="1" echo [WARN] Optional modules not installed:!OPTIONAL_MISSING!

exit /b 0

:error_exit
echo.
echo [ERROR] Installation failed.
echo [ERROR] Please check the errors above and try again.
pause
exit /b 1
