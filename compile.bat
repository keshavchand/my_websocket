@echo off
cl -Zi /Incremental:NO Crypt32.lib Advapi32.lib Ws2_32.lib main.cpp || pause
exit

