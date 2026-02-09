@echo off
REM Git LFS Auto-Installer for Windows
REM This script automatically installs Git LFS on Windows systems

echo ========================================
echo Git LFS Auto-Installer for Windows
echo ========================================
echo.

REM Check if Git LFS is already installed
git lfs version >nul 2>&1
if %errorlevel% == 0 (
    echo [INFO] Git LFS is already installed!
    git lfs version
    echo.
    echo [INFO] Running git lfs install to ensure it's configured...
    git lfs install
    echo.
    echo [SUCCESS] Git LFS is ready to use!
    pause
    exit /b 0
)

echo [INFO] Git LFS not found. Installing...
echo.

REM Try Chocolatey first
where choco >nul 2>&1
if %errorlevel% == 0 (
    echo [INFO] Found Chocolatey. Installing Git LFS...
    choco install git-lfs -y
    if %errorlevel% == 0 (
        echo [SUCCESS] Git LFS installed via Chocolatey!
        goto :initialize
    )
)

REM Try Scoop
where scoop >nul 2>&1
if %errorlevel% == 0 (
    echo [INFO] Found Scoop. Installing Git LFS...
    scoop install git-lfs
    if %errorlevel% == 0 (
        echo [SUCCESS] Git LFS installed via Scoop!
        goto :initialize
    )
)

REM Manual installation with Python script
echo [INFO] No package manager found. Using Python installer...
python install_git_lfs.py
if %errorlevel% == 0 (
    goto :initialize
)

REM If all else fails
echo.
echo [ERROR] Automatic installation failed!
echo.
echo Please install Git LFS manually:
echo   1. Visit: https://git-lfs.github.com/
echo   2. Download and run the installer
echo   3. Run this script again
echo.
pause
exit /b 1

:initialize
echo.
echo [INFO] Initializing Git LFS...
git lfs install
if %errorlevel% == 0 (
    echo.
    echo ========================================
    echo [SUCCESS] Git LFS is ready!
    echo ========================================
    echo.
    echo Next steps:
    echo   1. Run: python setup_git_lfs.py
    echo   2. Run your sync tool again
    echo   3. Large files will be uploaded to Git LFS
    echo.
) else (
    echo [WARN] Initialization failed. Please run: git lfs install
)

pause
exit /b 0
