@echo off
setlocal
set "CARDGUARD_DIR=%~dp0dist\client"
for %%F in (CardGuard.exe Qt6Core.dll Qt6Gui.dll Qt6Widgets.dll qt.conf platforms\qwindows.dll) do (
    if not exist "%CARDGUARD_DIR%\%%F" goto missing
)
start "CardGuard" /D "%CARDGUARD_DIR%" "%CARDGUARD_DIR%\CardGuard.exe"
exit /b %errorlevel%

:missing
echo CardGuard is not fully built, or a required runtime file is missing.
echo Open PowerShell 7 in this project and run:
echo   .\scripts\build.ps1
echo Keep the complete dist\client folder together when copying the app.
pause
exit /b 1
