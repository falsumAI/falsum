@echo off
REM Sentinel Uninstaller
echo Removing Sentinel...
del "%USERPROFILE%\Desktop\Sentinel.lnk" 2>nul
echo Desktop shortcut removed.
echo.
echo To complete removal, delete this folder manually.
echo Your vault logs in %%LOCALAPPDATA%%\Sentinel are preserved.
pause
