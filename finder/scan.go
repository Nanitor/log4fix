package finder

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// Finds war, ear and jar files and returns their absolute paths.
func Scan(dirPath string) ([]string, error) {
	compressedFiles := []string{}
	r, _ := regexp.Compile(`.*\.(jar|war|ear)`)
	fileCount := 0
	errCount := 0

	fmt.Println()
	filepath.Walk(dirPath,
		func(path string, info os.FileInfo, err error) error {
			fileCount++
			if err != nil {
				errCount++

				ErrorLogger.Printf("%v\n", err)
				if fileCount%1000 == 0 {
					IOLogger.Printf("Number of files scanned: %d \nNumber of files unable to access: %d\nNumber of JAR/WAR/EAR found: %d\n", fileCount, errCount, len(compressedFiles))
				}

				return nil
			}

			if fileCount%1000 == 0 {
				IOLogger.Printf("Number of files scanned: %d \nNumber of files unable to access: %d\nNumber of JAR/WAR/EAR found: %d\n", fileCount, errCount, len(compressedFiles))
			}

			filename := filepath.Base(path)
			if r.MatchString(filename) {
				compressedFiles = append(compressedFiles, path)
			}
			return nil
		})

	IOLogger.Printf("Number of files scanned: %d \nNumber of files unable to access: %d\nNumber of JAR/WAR/EAR found: %d\n", fileCount, errCount, len(compressedFiles))
	IOLogger.Close()

	return compressedFiles, nil
}
