# nmake Makefile

all: infector.exe delete_obj

infector.exe: infector.c logger.c
	cl /W4 infector.c logger.c /link /out:infector.exe

delete_obj:
	del /s /q infector.obj >nul 2>&1
	del /s /q logger.obj >nul 2>&1
