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
	err := filepath.Walk(dirPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			filename := filepath.Base(path)

			if r.MatchString(filename) {
				compressedFiles = append(compressedFiles, path)
			}
			return nil
		})
	if err != nil {
		return compressedFiles, err
	}
	return compressedFiles, nil
}
