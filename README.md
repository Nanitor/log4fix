# log4fix
This tool is to detect and fix the log4j log4shell vulnerability (CVE-2021-44228) by looking and removing the JndiLookup class from .jar/.war/.ear files with zero dependencies for free.
This tool has been tested on:
    - Linux 32bit and 64 bit
    - Windows 32 bit and 64 bit
    - OpenBSD 64 bit

This tool is written in the Go programming language which means zero dependencies and standalone binaries which will run everywhere.

## Install
Download binaries (Windows, Linux, Darwin, OpenBSD) here https://github.com/nanitor/log4fix/releases/tag/v4.0.0

## Usage

[![asciicast](https://asciinema.org/a/kQVtPYoz07W9MF8PidmYxQluy.svg)](https://asciinema.org/a/kQVtPYoz07W9MF8PidmYxQluy)

Scan file for vulnerability
```
log4fix detect </path/to/file.war>
```

Scan file for vulnerability and remove the vulnerable class.
```
log4fix fix </path/to/file.war> --overwrite
```

Scan single directory for vulnerability.
```
log4fix scan </path/to/dir>
```

Scan multiple directories for vulnerability.
```
log4fix scan </path/to/dir/1> </path/to/dir/2>
```

Scan directory for vulnerability and remove the vulnerable files. Note, this command overwrites the war/ear/jar files containing the vulnerable class that are found.
```
log4fix scan </path/to/dir> --fix
```

Scan directory for vulnerability and write the vulnerable jar/ear/war files found into the file supplied.
```
log4fix scan </path/to/dir> --output </path/to/text/file.txt>
```

We recommend taking a backup of the files prior to overwriting them.
On Windows, it may be necessary to stop the service prior to applying the fix.
Once the fix has been applied, the service should be restarted.

## Build from source
```
go build
```

## Note:
This is functionally equivalent to the recommended remediation of
```
zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```
except it can also go into other .jar/.war/.ear files and look for `log4j-core-*.jar` file in there and
removing the JndiLookup class from there.

And of course works on all platforms.
