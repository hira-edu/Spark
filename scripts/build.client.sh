export GO111MODULE=auto
export COMMIT=`git rev-parse HEAD`
export CGO_ENABLED=1



export GOOS=linux

export GOARCH=arm
export CC=arm-linux-gnueabihf-gcc
export CXX=arm-linux-gnueabihf-g++
go build -ldflags "-s -w -X 'Spark/client/config.Commit=$COMMIT'" -o ./built/linux_arm Spark/client

# Linux i386 requires multilib which conflicts with cross-compilers
# Building without CGO
export GOARCH=386
export CGO_ENABLED=0
unset CC
unset CXX
go build -ldflags "-s -w -X 'Spark/client/config.Commit=$COMMIT'" -o ./built/linux_i386 Spark/client
export CGO_ENABLED=1

export GOARCH=arm64
export CC=aarch64-linux-gnu-gcc
export CXX=aarch64-linux-gnu-g++
go build -ldflags "-s -w -X 'Spark/client/config.Commit=$COMMIT'" -o ./built/linux_arm64 Spark/client

export GOARCH=amd64
export CC=gcc
export CXX=g++
go build -ldflags "-s -w -X 'Spark/client/config.Commit=$COMMIT'" -o ./built/linux_amd64 Spark/client



export GOOS=windows

export GOARCH=386
export CC=i686-w64-mingw32-gcc
export CXX=i686-w64-mingw32-g++
go build -ldflags "-s -w -H=windowsgui -X 'Spark/client/config.Commit=$COMMIT'" -o ./built/windows_i386.exe Spark/client

export GOARCH=amd64
export CC=x86_64-w64-mingw32-gcc
export CXX=x86_64-w64-mingw32-g++
go build -ldflags "-s -w -H=windowsgui -X 'Spark/client/config.Commit=$COMMIT'" -o ./built/windows_amd64.exe Spark/client

# Windows ARM64 requires special cross-compiler (not available in standard Ubuntu repos)
# Building without CGO for now
export GOARCH=arm64
export CGO_ENABLED=0
unset CC
unset CXX
go build -ldflags "-s -w -H=windowsgui -X 'Spark/client/config.Commit=$COMMIT'" -o ./built/windows_arm64.exe Spark/client
export CGO_ENABLED=1

# Server looks for binaries without .exe extension
# Copy Windows binaries to names without extension
cp -f ./built/windows_386.exe ./built/windows_386
cp -f ./built/windows_amd64.exe ./built/windows_amd64
cp -f ./built/windows_arm64.exe ./built/windows_arm64
cp -f ./built/windows_i386.exe ./built/windows_i386
