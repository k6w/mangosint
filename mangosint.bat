@echo off
REM Windows launcher for mangosint

set PYTHONPATH=%~dp0src
python -m mangosint.cli %*