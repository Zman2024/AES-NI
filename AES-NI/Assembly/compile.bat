@echo off
cd /d %~dp0%
echo ========== Assembling "aes-ni.asm" ==========
nasm -f bin aes-ni.asm -o bin/libaes.dll
copy bin/libaes.dll ../libaes.dll
pause