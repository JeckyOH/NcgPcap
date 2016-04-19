@echo off

set root_dir="%~dp0"
set script_dir="%root_dir%\script\"
set rsc_dir="%root_dir%\ui\rsc"

cd %script_dir%
python "setup.py"
rd /s /q "%script_dir%\build"

xcopy "%rsc_dir%" "%root_dir%\bin\win32\rsc" /s /e /h

del "%root_dir%\bin\win32\NcgPcap.exe"
rename "%root_dir%\bin\win32\MainWindow.exe" NcgPcap.exe
