@echo off
setlocal enableextensions
pushd "%~dp0"

echo.
echo === ReticulumTUN build ===
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo [X] Python not found.
    exit /b 1
)

if not exist ".venv" (
    echo [*] Creating .venv ...
    python -m venv .venv || goto :err
)
call .venv\Scripts\activate.bat || goto :err

echo [*] Installing dependencies ...
python -m pip install --upgrade pip || goto :err
python -m pip install pyinstaller rns || goto :err

echo [*] Building tun_rns_win.exe ...

if exist "wintun\bin\amd64\wintun.dll" (
    set "WT_SRC=wintun\bin\amd64\*.dll"
    set "WT_DST=wintun\amd64"
) else if exist "wintun\amd64\wintun.dll" (
    set "WT_SRC=wintun\amd64\*.dll"
    set "WT_DST=wintun\amd64"
) else (
    echo [!] wintun.dll not found. TUN will not work, but exe will build.
    set "WT_SRC="
    set "WT_DST="
)

if defined WT_SRC (
    pyinstaller --noconfirm --onefile --windowed ^
        --add-data "%WT_SRC%;%WT_DST%" ^
        tun_rns_win.py || goto :err
) else (
    pyinstaller --noconfirm --onefile --windowed ^
        tun_rns_win.py || goto :err
)

echo.
echo [+] Done: dist\tun_rns_win.exe
echo.
popd
endlocal
exit /b 0

:err
echo.
echo [X] Build FAILED
popd
endlocal
exit /b 1
