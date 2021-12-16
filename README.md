# log4fix
This tool is to detect and fix log4j by looking and removing the JndiLookup class from .jar/.war/.ear files with zero dependencies for free.
This tool has been tested on:
    - Linux 32bit and 64 bit
    - Windows 32 bit and 64 bit
    - OpenBSD 64 bit

This tool is written in the Go programming language which means zero dependencies and standalone binaries which will run everywhere.

## Prerequisites
For this to work we need to create an account in UniCloud to get a free license key. This is only to load the license and it will send home statistics on how many documents have been used, it does not send any documents or anything. The free key gives us 100 documents a month for free which is more than enough for most CLI cases.
See https://help.unidoc.io/article/142-how-to-sign-up-for-unicloud and https://help.unidoc.io/article/141-metered-license-api-key to how to get started to get the key.

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
