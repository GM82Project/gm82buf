del build64\src\release\gm82buf.dll

cmake -B build64 -A x64 -DNO_GEX=ON && cmake --build build64 --config Release
copy build64\src\Release\gm82buf.dll .

pause
