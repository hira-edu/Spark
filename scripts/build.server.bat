set GO111MODULE=auto
for /F %%i in ('git rev-parse HEAD') do ( set COMMIT=%%i)
if "%CGO_ENABLED%"=="" set CGO_ENABLED=1



set GOOS=darwin

set GOARCH=arm64
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=%COMMIT%'" -tags=jsoniter -o ./releases/server_darwin_arm64 Rocket/server
set GOARCH=amd64
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=%COMMIT%'" -tags=jsoniter -o ./releases/server_darwin_amd64 Rocket/server



set GOOS=linux

set GOARCH=arm
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=%COMMIT%'" -tags=jsoniter -o ./releases/server_linux_arm Rocket/server
set GOARCH=386
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=%COMMIT%'" -tags=jsoniter -o ./releases/server_linux_i386 Rocket/server
set GOARCH=arm64
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=%COMMIT%'" -tags=jsoniter -o ./releases/server_linux_arm64 Rocket/server
set GOARCH=amd64
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=%COMMIT%'" -tags=jsoniter -o ./releases/server_linux_amd64 Rocket/server



set GOOS=windows

set GOARCH=386
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=%COMMIT%'" -tags=jsoniter -o ./releases/server_windows_i386.exe Rocket/server
set GOARCH=arm64
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=%COMMIT%'" -tags=jsoniter -o ./releases/server_windows_arm64.exe Rocket/server
set GOARCH=amd64
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=%COMMIT%'" -tags=jsoniter -o ./releases/server_windows_amd64.exe Rocket/server
