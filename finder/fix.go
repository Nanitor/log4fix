package finder

import (
	"archive/zip"
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const tempPrefix = "temp1606"

func readZip(zipPath string) *zip.Reader {
	buff, err := os.ReadFile(zipPath)
	if err != nil {
		ErrorLogger.Printf("%v\n", err)
		return nil
	}

	r, err := zip.NewReader(bytes.NewReader(buff), int64(len(buff)))
	if err != nil {
		ErrorLogger.Printf("%v\n", err)
		return nil
	}

	return r
}

func isLog4Jar(name string) bool {
	return Log4jJarFileNames[strings.ToLower(name)]
}

func FixFile(zipPath string, filesToSkip []string) {

	zipReader := readZip(zipPath)
	if zipReader == nil {
		return
	}

	tempZipPath := tempPrefix + filepath.Base(zipPath) // This will be deleted
	newZipFile, err := os.Create(tempZipPath)
	if err != nil {
		ErrorLogger.Printf("%v\n", err)
		return
	}
	defer os.Remove(tempZipPath) // If the actions fail, i.e. error, then the temp file will be removed.
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()

	if isLog4Jar(filepath.Base(zipPath)) {
		err = ZipFiles(filesToSkip, tempZipPath, zipReader.File, zipWriter)
		if err != nil {
			ErrorLogger.Printf("%v\n", err)
			return
		}
	} else {
		for _, file := range zipReader.File {
			// Loop through the files, searching for log4jar.
			if isLog4Jar(filepath.Base(file.Name)) {
				path, err := createLog4JarWithoutJndi(file, filesToSkip)
				defer os.Remove(path) // delete the file created by the above function. Clean up.
				if err != nil {
					ErrorLogger.Printf("%v", err)
					return
				}

				buff2, err := os.ReadFile(path)
				if err != nil {
					ErrorLogger.Printf("%v\n", err)
					return
				}

				ioWr, err := zipWriter.Create(file.Name)
				if err != nil {
					ErrorLogger.Printf("%v\n", err)
					return
				}

				_, err = ioWr.Write(buff2)
				if err != nil {
					ErrorLogger.Printf("%v\n", err)
					return
				}
			} else {
				AddFileToZip(zipWriter, file)
			}
		}

		if err != nil {
			ErrorLogger.Printf("%v\n", err)
			return
		}
	}

	err = os.Remove(zipPath)
	if err != nil {
		ErrorLogger.Printf("%v\n", err)
		return
	}

	err = os.Rename(tempZipPath, zipPath)
	if err != nil {
		ErrorLogger.Printf("%v\n", err)
		return
	}
}

func createLog4JarWithoutJndi(file *zip.File, deleteFilenames []string) (string, error) {
	fr, err := file.Open()
	if err != nil {
		return "", err
	}

	tempJarPath := tempPrefix + filepath.Base(file.Name)

	// ReadAll reads from readCloser until EOF and returns the data as a []byte
	b, err := ioutil.ReadAll(fr) // The readCloser is the one from the zip-package
	if err != nil {
		return "", err
	}

	// bytes.Reader implements io.Reader, io.ReaderAt, etc. All you need!
	readerAt := bytes.NewReader(b)

	r, err := zip.NewReader(readerAt, int64(file.UncompressedSize64))
	if err != nil {
		return tempJarPath, err
	}

	newZipFile, err := os.Create(tempJarPath)
	if err != nil {
		return tempJarPath, err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()
	for _, file := range r.File {
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
			return tempJarPath, err
		}
	}

	return tempJarPath, nil
}

// ZipFiles compresses one or many files into a single zip archive file.
// Param 1: filename is the output zip file's name.
// Param 2: files is a list of files to add to the zip.
func ZipFiles(deleteFilenames []string, filename string, files []*zip.File, zipWriter *zip.Writer) error {

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
		if err := AddFileToZip(zipWriter, file); err != nil {
			return err
		}
	}
	return nil
}

// Adds file to the new zip.
func AddFileToZip(zipWriter *zip.Writer, file *zip.File) error {

	zipItemReader, err := file.Open()

	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(file.FileInfo())
	if err != nil {
		return err
	}

	header.Method = zip.Deflate

	header.Name = file.Name
	targetItem, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(targetItem, zipItemReader)

	return err
}
