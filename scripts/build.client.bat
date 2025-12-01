set GO111MODULE=auto
for /F %%i in ('git rev-parse HEAD') do ( set COMMIT=%%i)



set GOOS=linux

set GOARCH=arm
go build -ldflags "-s -w -X 'Rocket/client/config.Commit=%COMMIT%'" -o ./built/linux_arm Rocket/client
set GOARCH=386
go build -ldflags "-s -w -X 'Rocket/client/config.Commit=%COMMIT%'" -o ./built/linux_i386 Rocket/client
set GOARCH=arm64
go build -ldflags "-s -w -X 'Rocket/client/config.Commit=%COMMIT%'" -o ./built/linux_arm64 Rocket/client
set GOARCH=amd64
go build -ldflags "-s -w -X 'Rocket/client/config.Commit=%COMMIT%'" -o ./built/linux_amd64 Rocket/client



set GOOS=windows

set GOARCH=386
go build -ldflags "-s -w -H=windowsgui -X 'Rocket/client/config.Commit=%COMMIT%'" -o ./built/windows_i386.exe Rocket/client
set GOARCH=arm64
go build -ldflags "-s -w -H=windowsgui -X 'Rocket/client/config.Commit=%COMMIT%'" -o ./built/windows_arm64.exe Rocket/client
set GOARCH=amd64
go build -ldflags "-s -w -H=windowsgui -X 'Rocket/client/config.Commit=%COMMIT%'" -o ./built/windows_amd64.exe Rocket/client



@REM set GOOS=android
@REM set CGO_ENABLED=1

@REM set GOARCH=arm
@REM set CC=armv7a-linux-androideabi21-clang
@REM set CXX=armv7a-linux-androideabi21-clang++
@REM go build -ldflags "-s -w -X 'Rocket/client/config.Commit=%COMMIT%'" -o ./built/android_arm Rocket/client

@REM set GOARCH=386
@REM set CC=i686-linux-android21-clang
@REM set CXX=i686-linux-android21-clang++
@REM go build -ldflags "-s -w -X 'Rocket/client/config.Commit=%COMMIT%'" -o ./built/android_i386 Rocket/client

@REM set GOARCH=arm64
@REM set CC=aarch64-linux-android21-clang
@REM set CXX=aarch64-linux-android21-clang++
@REM go build -ldflags "-s -w -X 'Rocket/client/config.Commit=%COMMIT%'" -o ./built/android_arm64 Rocket/client

@REM set GOARCH=amd64
@REM set CC=x86_64-linux-android21-clang
@REM set CXX=x86_64-linux-android21-clang++
@REM go build -ldflags "-s -w -X 'Rocket/client/config.Commit=%COMMIT%'" -o ./built/android_amd64 Rocket/client
