@echo off
REM ===================================================================
REM  Compile the Informatica BOLA sweep tool into standalone binaries.
REM
REM  Produces in .\dist:
REM    bola.exe      - CLI engine (console)
REM    bola-gui.exe  - desktop GUI (windowed, no console)
REM
REM  The official swagger is embedded in swagger_data.py (plain Python),
REM  so it is compiled into the .exe - no data files. CustomTkinter theme
REM  assets are bundled into the GUI build automatically.
REM
REM  Usage:
REM    build.bat                 build both (onefile)
REM    build.bat --gui-only
REM    build.bat --cli-only
REM    build.bat --onedir        folder instead of one file (faster start)
REM    build.bat --clean         remove build\ dist\ *.spec first
REM    build.bat --icon app.ico
REM ===================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "BUILD_GUI=1"
set "BUILD_CLI=1"
set "ONEFILE=--onefile"
set "DO_CLEAN=0"
set "ICONPATH="

REM ---- parse arguments ----
:parse
if "%~1"=="" goto after
if defined WANT_ICON (
    set "ICONPATH=%~1"
    set "WANT_ICON="
    shift
    goto parse
)
if /I "%~1"=="--icon"     ( set "WANT_ICON=1"       & shift & goto parse )
if /I "%~1"=="--gui-only" ( set "BUILD_CLI=0"       & shift & goto parse )
if /I "%~1"=="--cli-only" ( set "BUILD_GUI=0"       & shift & goto parse )
if /I "%~1"=="--onedir"   ( set "ONEFILE=--onedir"  & shift & goto parse )
if /I "%~1"=="--clean"    ( set "DO_CLEAN=1"        & shift & goto parse )
echo Unknown option: %~1
shift
goto parse
:after

set "ICON="
if defined ICONPATH set "ICON=--icon "%ICONPATH%""

REM ---- locate Python ----
where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: python not found on PATH.
    exit /b 1
)

REM ---- ensure PyInstaller ----
python -c "import PyInstaller" >nul 2>nul
if errorlevel 1 (
    echo PyInstaller not found - installing...
    python -m pip install pyinstaller
    if errorlevel 1 ( echo ERROR: failed to install PyInstaller. & exit /b 1 )
)

REM ---- bundle CustomTkinter assets only if it is installed ----
set "CTK="
python -c "import customtkinter" >nul 2>nul
if not errorlevel 1 set "CTK=--collect-all customtkinter"

REM ---- bundle openpyxl (Excel export) if installed; exclude Pillow/matplotlib to stay lean ----
set "XLSX="
python -c "import openpyxl" >nul 2>nul
if not errorlevel 1 set "XLSX=--hidden-import openpyxl --hidden-import openpyxl.cell._writer --exclude-module PIL --exclude-module matplotlib --exclude-module numpy --exclude-module pandas"

REM ---- optional clean ----
if "%DO_CLEAN%"=="1" (
    echo Cleaning build\ dist\ *.spec ...
    if exist build rmdir /s /q build
    if exist dist  rmdir /s /q dist
    del /q *.spec >nul 2>nul
)

REM ---- build CLI ----
if "%BUILD_CLI%"=="1" (
    echo.
    echo === Building CLI binary: bola ===
    python -m PyInstaller --noconfirm --clean --name bola ^
        --distpath dist --workpath build --specpath . ^
        %ONEFILE% --console %XLSX% %ICON% --paths . bola_sweep.py
    if errorlevel 1 ( echo ERROR: CLI build failed. & exit /b 1 )
)

REM ---- build GUI ----
if "%BUILD_GUI%"=="1" (
    echo.
    echo === Building GUI binary: bola-gui ===
    python -m PyInstaller --noconfirm --clean --name bola-gui ^
        --distpath dist --workpath build --specpath . ^
        %ONEFILE% --windowed %CTK% %XLSX% %ICON% --paths . bola_gui.py
    if errorlevel 1 ( echo ERROR: GUI build failed. & exit /b 1 )
)

echo.
echo Done. Binaries in .\dist:
if "%BUILD_CLI%"=="1" if exist dist\bola.exe     echo    dist\bola.exe
if "%BUILD_GUI%"=="1" if exist dist\bola-gui.exe echo    dist\bola-gui.exe
echo.
echo Tip: these are unsigned; Windows SmartScreen / AV may warn on first run.
endlocal
