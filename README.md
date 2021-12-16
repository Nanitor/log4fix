# log4fix
This tool is to detect and fix log4j by looking and removing the JndiLookup class from .jar/.war/.ear files with zero dependencies for free.
This tool has been tested on:
    - Linux 32bit and 64 bit
    - Windows 32 bit and 64 bit
    - OpenBSD 64 bit

This tool is written in the Go programming language which means zero dependencies and standalone binaries which will run everywhere.

## Install
Download binaries (Darwin, Linux, OpenBSD, Windows) here https://github.com/nanitor/log4fix/releases/tag/v0.0.1.

## Usage
```
./log4fix </path/to/file.war>
```

## Build from source
```
go build
```
