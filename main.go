package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"

	"github.com/nanitor/log4fix/finder"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Usage = "Log 4 Shell fix"
	app.Version = "0.0.0"

	app.Commands = []cli.Command{

		{
			Name:  "scan_jar_log4j",
			Usage: "Scan file system for log4j vulnerability",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "path",
					Value: "",
					Usage: "Full path the jar file to be scanned for vulnerability, e.g. /tmp/bigfix.jar",
				},
				&cli.BoolFlag{
					Name:  "fix",
					Usage: "Fix the vulnerability if it exists",
				},
			},
			Action: func(c *cli.Context) {
				warPath := c.String("path")

				if len(warPath) > 0 {
					hasLog4Jar, isVuln, path, err := finder.ArchiveVulnerableLog4shell(warPath)
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}

					if hasLog4Jar {
						if isVuln {
							fmt.Printf("Log4 jar file found - Vulnerable - has class\n PathToFile %s\n", path)

							if c.Bool("fix") {
								fmt.Printf("\nDeleting %s\n", path)
								finder.FixFile(warPath, []string{path})
							}
						} else {
							fmt.Printf("Log4 jar file found - NOT Vulnerable - missing class\n")
						}
					} else {
						fmt.Printf("Not vulnerable\n")
					}
				} else {
					fmt.Println("Please set flags --path or --fdb")
				}
			},
		},

		{
			Name:  "diff_jar_files",
			Usage: "Compare diff of two jar files",
			Flags: []cli.Flag{},
			Action: func(c *cli.Context) {
				files := c.Args()
				file1 := files.Get(0)
				file2 := files.Get(1)

				buff, err := os.ReadFile(file1)
				if err != nil {
					fmt.Printf("Reading zip-file err: %v\n", err)
					return
				}

				r1, err := zip.NewReader(bytes.NewReader(buff), int64(len(buff)))
				if err != nil {
					fmt.Printf("Unzipping zip err: %v\n", err)
					return
				}

				buff, err = os.ReadFile(file2)
				if err != nil {
					fmt.Printf("Reading zip-file err: %v\n", err)
					return
				}

				r2, err := zip.NewReader(bytes.NewReader(buff), int64(len(buff)))
				if err != nil {
					fmt.Printf("Unzipping zip err: %v\n", err)
					return
				}

				onlyIn1 := []*zip.File{}
				for _, rfile1 := range r1.File {
					isIn2 := false
					for j, rfile2 := range r2.File {
						if isSameFile(rfile1, rfile2) {
							r2.File = remove(r2.File, j)
							isIn2 = true
							break
						}
					}

					if !isIn2 {
						onlyIn1 = append(onlyIn1, rfile1)
					}
				}

				if len(onlyIn1) > 0 {
					fmt.Printf("\nFiles only in %s:\n\n", file1)
					for _, file := range onlyIn1 {
						fmt.Printf("%s\n", file.Name)
					}
				}

				if len(r2.File) > 0 {
					fmt.Printf("\nFiles only in %s:\n\n", file2)

					for _, file := range r2.File {
						fmt.Printf("%s\n", file.Name)
					}
					fmt.Println()
				}

			},
		},
	}

	app.Run(os.Args)
}

func isSameFile(file1 *zip.File, file2 *zip.File) bool {
	if file1.Name != file2.Name {
		return false
	}

	// frc, _ := file1.Open()
	// // if err != nil {
	// // 	return false
	// // }
	// bufN := file1.FileInfo().Size()
	// buf := make([]byte, bufN)
	// n, _ := io.ReadFull(frc, buf)
	// buf = buf[:n]
	// defer frc.Close()

	// frc2, _ := file1.Open()
	// // if err != nil {
	// // 	return false
	// // }
	// bufN2 := file2.FileInfo().Size()
	// buf2 := make([]byte, bufN2)
	// n2, _ := io.ReadFull(frc2, buf2)
	// buf = buf[:n2]
	// defer frc2.Close()

	// if bufN != bufN2 {
	// 	fmt.Println("BUFFER", bufN, bufN2)
	// 	return false
	// }

	return true
}

func remove(s []*zip.File, i int) []*zip.File {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}

// diff -y <(unzip -l test.jar) <(unzip -l log4j-core-2.9.0.jar)
