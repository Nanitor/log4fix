package finder

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var log4jJarFileNames = map[string]bool{
	"log4j-core-2.0-alpha1.jar": true,
	"log4j-core-2.0-alpha2.jar": true,
	"log4j-core-2.0-beta1.jar":  true,
	"log4j-core-2.0-beta2.jar":  true,
	"log4j-core-2.0-beta3.jar":  true,
	"log4j-core-2.0-beta4.jar":  true,
	"log4j-core-2.0-beta5.jar":  true,
	"log4j-core-2.0-beta6.jar":  true,
	"log4j-core-2.0-beta7.jar":  true,
	"log4j-core-2.0-beta8.jar":  true,
	"log4j-core-2.0-beta9.jar":  true,
	"log4j-core-2.0.jar":        true,
	"log4j-core-2.0-rc1.jar":    true,
	"log4j-core-2.0-rc2.jar":    true,
	"log4j-core-2.0.1.jar":      true,
	"log4j-core-2.0.2.jar":      true,
	"log4j-core-2.1.jar":        true,
	"log4j-core-2.2.jar":        true,
	"log4j-core-2.3.jar":        true,
	"log4j-core-2.4.jar":        true,
	"log4j-core-2.4.1.jar":      true,
	"log4j-core-2.5.jar":        true,
	"log4j-core-2.6.jar":        true,
	"log4j-core-2.6.1.jar":      true,
	"log4j-core-2.6.2.jar":      true,
	"log4j-core-2.7.jar":        true,
	"log4j-core-2.8.jar":        true,
	"log4j-core-2.8.1.jar":      true,
	"log4j-core-2.8.2.jar":      true,
	"log4j-core-2.9.0.jar":      true,
	"log4j-core-2.9.1.jar":      true,
	"log4j-core-2.10.0.jar":     true,
	"log4j-core-2.11.0.jar":     true,
	"log4j-core-2.11.1.jar":     true,
	"log4j-core-2.11.2.jar":     true,
	"log4j-core-2.12.0.jar":     true,
	"log4j-core-2.12.1.jar":     true,
	"log4j-core-2.13.0.jar":     true,
	"log4j-core-2.13.1.jar":     true,
	"log4j-core-2.13.2.jar":     true,
	"log4j-core-2.13.3.jar":     true,
	"log4j-core-2.14.0.jar":     true,
	"log4j-core-2.14.1.jar":     true,
	"log4j-core-2.15.0.jar":     true,
}

// traverseArchive traveses a zip archive and executes traverseFn for each file.
func traverseArchive(rs io.ReadSeeker, traverseFn func(file *zip.File) error) error {
	rsa := readSeekerAt{
		rs: rs,
	}

	zr, err := zip.NewReader(rsa, rsa.Len())
	if err != nil {
		return err
	}
	count := 0
	const maxCountLimit = 1000000
	for _, f := range zr.File {
		err := traverseFn(f)
		if err != nil {
			return err
		}
		count++
		if count > maxCountLimit {
			// Stop searching if too many files traversed.
			// Just to have some limit.. but this shouldn't be too inefficient.
			break
		}
	}
	return nil
}

var errEarlyExit = errors.New("early exit code")

func isVulnLog4JarArchive(rs io.ReadSeeker) (bool, string) {
	hasClass := false
	path := ""
	traverseArchive(rs, func(file *zip.File) error {

		if file.FileInfo().IsDir() {
			return nil
		}
		baseName := filepath.Base(file.Name)

		// org/apache/logging/log4j/core/lookup/JndiLookup.class
		if strings.ToLower(baseName) == `jndilookup.class` {
			path = file.Name
			hasClass = true
			return errEarlyExit
		}
		return nil
	})
	if hasClass {
		// Vulnerable.
		return true, path
	}
	return false, ""
}

func ArchiveVulnerableLog4shell(filePath string) (hasLog4Jar bool, isVuln bool, path string, err error) {
	basename := filepath.Base(filePath)
	isLog4Jar := log4jJarFileNames[basename]

	f, err := os.Open(filePath)
	if err != nil {
		return false, false, "", err
	}
	defer f.Close()
	if isLog4Jar {
		isVuln, path := isVulnLog4JarArchive(f)
		fmt.Println(isVuln, path, filePath)
		return true, isVuln, path, nil
	}

	vulnerable := false
	hasLog4Jar = false
	pathToVulnFile := ""
	traverseArchive(f, func(file *zip.File) error {
		if file.FileInfo().IsDir() {
			return nil
		}
		if file.FileInfo().Size() > 10*1000*1000 {
			// Should be under 10mb for sure.
			return nil
		}
		basename := strings.ToLower(filepath.Base(file.Name))
		isLog4Jar := log4jJarFileNames[basename]
		if isLog4Jar {
			hasLog4Jar = true
			frc, err := file.Open()
			if err != nil {
				return err
			}
			bufN := file.FileInfo().Size()
			buf := make([]byte, bufN)
			n, _ := io.ReadFull(frc, buf)
			buf = buf[:n]
			frc.Close()

			if isVuln, path := isVulnLog4JarArchive(bytes.NewReader(buf)); isVuln {
				vulnerable = true
				pathToVulnFile = path
				return errEarlyExit
			}
		}
		return nil
	})

	return hasLog4Jar, vulnerable, pathToVulnFile, nil
}

// readSeekerAt implements io.ReaderAt on top of an io.ReadSeeker.
type readSeekerAt struct {
	rs io.ReadSeeker
}

func (rsa readSeekerAt) Len() int64 {
	cur, _ := rsa.rs.Seek(0, io.SeekCurrent)
	defer rsa.rs.Seek(cur, io.SeekStart)
	off, _ := rsa.rs.Seek(0, io.SeekEnd)
	return off
}

func (rsa readSeekerAt) ReadAt(p []byte, off int64) (n int, err error) {
	rsa.rs.Seek(off, io.SeekStart)
	return rsa.rs.Read(p)
}
