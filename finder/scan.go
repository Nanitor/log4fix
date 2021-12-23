package finder

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// Finds war, ear and jar files and returns their absolute paths.
func Scan(dirPaths []string) ([]string, error) {
	compressedFiles := []string{}
	for _, dirPath := range dirPaths {
		files, _ := ScanDir(dirPath)
		compressedFiles = append(compressedFiles, files...)
	}
	return compressedFiles, nil
}

func ScanDir(dirPath string) ([]string, error) {
	compressedFiles := []string{}
	rJar, _ := regexp.Compile(`.*\.jar`)
	rWar, _ := regexp.Compile(`.*\.war`)
	rEar, _ := regexp.Compile(`.*\.ear`)
	fileCount := 0
	errCount := 0
	jarFileCount := 0
	warFileCount := 0
	earCount := 0

	fmt.Printf("\nScanning %s\n\n", dirPath)
	IOLogger.Printf("Scanning %s\n", dirPath)
	filepath.Walk(dirPath,
		func(path string, info os.FileInfo, err error) error {
			fileCount++
			if err != nil {
				errCount++

				ErrorLogger.Printf("%v\n", err)
				if fileCount%1000 == 0 {
					IOLogger.Printf("Number of files scanned: %d \nNumber of files unable to access: %d\nNumber of .JAR found: %d\nNumber of .WAR found: %d\nNumber of .EAR found: %d\n", fileCount, errCount, jarFileCount, warFileCount, earCount)
				}

				return nil
			}

			filename := filepath.Base(path)

			if rJar.MatchString(filename) {
				compressedFiles = append(compressedFiles, path)
				jarFileCount++
			} else if rWar.MatchString(filename) {
				compressedFiles = append(compressedFiles, path)
				warFileCount++
			} else if rEar.MatchString(filename) {
				compressedFiles = append(compressedFiles, path)
				earCount++
			}

			if fileCount%1000 == 0 {
				IOLogger.Printf("Number of files scanned: %d \nNumber of files unable to access: %d\nNumber of .JAR found: %d\nNumber of .WAR found: %d\nNumber of .EAR found: %d\n", fileCount, errCount, jarFileCount, warFileCount, earCount)
			}
			return nil
		})

	IOLogger.Printf("Number of files scanned: %d \nNumber of files unable to access: %d\nNumber of .JAR found: %d\nNumber of .WAR found: %d\nNumber of .EAR found: %d\n", fileCount, errCount, jarFileCount, warFileCount, earCount)
	IOLogger.Close()

	return compressedFiles, nil
}
