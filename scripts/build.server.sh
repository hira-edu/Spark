export GO111MODULE=auto
export COMMIT=`git rev-parse HEAD`
# Disable CGO for server builds (not needed and allows easy cross-compilation)
export CGO_ENABLED=0


export GOOS=darwin

export GOARCH=arm64
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" -tags=jsoniter -o ./releases/server_darwin_arm64 Rocket/server
export GOARCH=amd64
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" -tags=jsoniter -o ./releases/server_darwin_amd64 Rocket/server



export GOOS=linux

export GOARCH=arm
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" -tags=jsoniter -o ./releases/server_linux_arm Rocket/server
export GOARCH=386
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" -tags=jsoniter -o ./releases/server_linux_i386 Rocket/server
export GOARCH=arm64
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" -tags=jsoniter -o ./releases/server_linux_arm64 Rocket/server
export GOARCH=amd64
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" -tags=jsoniter -o ./releases/server_linux_amd64 Rocket/server



export GOOS=windows

export GOARCH=386
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" -tags=jsoniter -o ./releases/server_windows_i386.exe Rocket/server
export GOARCH=arm64
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" -tags=jsoniter -o ./releases/server_windows_arm64.exe Rocket/server
export GOARCH=amd64
go build -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" -tags=jsoniter -o ./releases/server_windows_amd64.exe Rocket/server
