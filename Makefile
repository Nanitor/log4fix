all:
	go build -o bin/log4fix

all-linux32:
	GOOS=linux GOARCH=386 go build -o bin/log4fix-linux32

all-linux64:
	GOOS=linux GOARCH=amd64 go build -o bin/log4fix-linux64

all-openbsd64:
	GOOS=openbsd GOARCH=amd64 go build -o bin/log4fix-openbsd64

all-openbsd32:
	GOOS=openbsd GOARCH=386 go build -o bin/log4fix-openbsd32

all-openbsd: all-openbsd64
all-linux: all-linux64
