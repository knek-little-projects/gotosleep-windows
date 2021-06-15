@echo off

rem echo > C:\smartlock.log

FOR /L %%i IN (1,1,60) DO (
	C:\Users\admin\Documents\smartlock\smartlock.py
	rem  >> C:\smartlock.log 2>&1
	timeout 1 > NUL
)
