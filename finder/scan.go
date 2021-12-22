package finder

import (
	"os"
	"path/filepath"
	"regexp"
)

// Finds war, ear and jar files and returns their absolute paths.
func Scan(dirPath string) ([]string, error) {
	compressedFiles := []string{}
	r, _ := regexp.Compile(`.*\.(jar|war|ear)`)
	filepath.Walk(dirPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				ErrorLogger.Printf("%v\n", err)
				return nil
			}
			filename := filepath.Base(path)

			if r.MatchString(filename) {
				compressedFiles = append(compressedFiles, path)
			}
			return nil
		})
	return compressedFiles, nil
}
