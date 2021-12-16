package finder

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
)

func FixFile(zipName string, filesToDelete []string) {
	buff, err := os.ReadFile(zipName)
	if err != nil {
		fmt.Printf("Reading zip-file err: %v\n", err)
		return
	}

	r, err := zip.NewReader(bytes.NewReader(buff), int64(len(buff)))
	if err != nil {
		fmt.Printf("Unzipping zip err: %v\n", err)
		return
	}

	err = ZipFiles(filesToDelete, zipName, r.File)
	if err != nil {
		fmt.Printf("Zipping new file err: %v\n", err)
		return
	}
}

// ZipFiles compresses one or many files into a single zip archive file.
// Param 1: filename is the output zip file's name.
// Param 2: files is a list of files to add to the zip.
func ZipFiles(deleteFilenames []string, filename string, files []*zip.File) error {

	newZipFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()

	// Add files to zip
	for _, file := range files {
		foundMatch := false
		for _, deleteFilename := range deleteFilenames {
			if deleteFilename == file.Name {
				foundMatch = true
				break
			}
		}
		if foundMatch {
			continue
		}
		if err = AddFileToZip(zipWriter, file); err != nil {
			return err
		}
	}
	return nil
}

func AddFileToZip(zipWriter *zip.Writer, file *zip.File) error {

	// Get the file information
	info := file.FileInfo()

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}

	// Using FileInfoHeader() above only uses the basename of the file. If we want
	// to preserve the folder structure we can overwrite this with the full path.
	header.Name = file.Name

	// Change to deflate to gain better compression
	// see http://golang.org/pkg/archive/zip/#pkg-constants
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	fileWriter, err := file.OpenRaw()
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, fileWriter)
	return err
}
