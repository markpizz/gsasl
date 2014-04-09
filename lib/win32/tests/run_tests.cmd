    @echo off
    rem arg 1 is the relative path to the binaries to test using \ as directory separator
    set TEST_BINARIES=%1
    rem arg 2 is the relative path to the binaries to test using \ as directory separator
    set TEST_SOURCE=%2
    rem arg 3 is the path to the output file to be produced when all tests are successful using \ as a directory separator
    set TEST_OUTPUT=%3
    set RUN_TESTS_CMD=%0
    set CONFIG_H=%~p0\..\include\config.h
    echo Running test command procedure: '%RUN_TESTS_CMD%'
    echo Success will create the output file: %TEST_OUTPUT%
    if exist %TEST_OUTPUT% del %TEST_OUTPUT%
    set _STATUS=0
    echo.
    echo Running Tests:
    echo.
    for %%f in (*.vc*proj) do call :do_test %%f%
    if %_STATUS% EQU 0 echo All Tests Good >%TEST_OUTPUT%
    exit /B %_STATUS%

:do_test
    set _TEST=%~n1
    if not %_STATUS% EQU 0 goto :EOF
    if "%_TEST%" == "libgsasl" goto :EOF
    if "%_TEST%" == "run_all_tests" goto :EOF
    echo.   
    echo Testing %_TEST% ...
    if not exist %TEST_BINARIES%\%_TEST%.exe set _STATUS=2
    if not exist %TEST_BINARIES%\%_TEST%.exe exit /b %_STATUS%
    pushd ..\..\..\tests
    ..\lib\win32\tests\%TEST_BINARIES%\%_TEST%.exe
    set _STATUS=%ERRORLEVEL%
    popd
    if %_STATUS% EQU 0 goto :EOF
    set _FEATURE=
    for /F "tokens=1,2,3" %%l in (%RUN_TESTS_CMD%) do if "%%l%%m" == "::%_TEST%" set _FEATURE=%%n

    rem if no specific feature was found, then return the test failure status
    if "%_FEATURE%" == "" goto :EOF
    echo Test %_TEST% requires libgsasl built with %_FEATURE%

    rem ignore the failure if libgsasl wasn't build with the known needed feature
    set _FEATURE_FOUND=
    for /F "tokens=1,2,3" %%l in (%CONFIG_H%) do if "%%l %%m %%n" == "#define %_FEATURE% 1" set _FEATURE_FOUND=1
    if "%_FEATURE_FOUND%" == "1" goto :EOF
    set _STATUS=0
    goto :EOF

rem this table lists the tests which are known to fail if libgsasl 
rem hasn't been built with a specific features.

rem  test      required feature
rem ===========================
::   saml20    USE_SAML20
::   openid20  USE_OPENID20
::   gs2-krb5  USE_GS2
::   gssapi    USE_GSSAPI
