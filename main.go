package main

import (
	"fmt"
	"os"

	"github.com/nanitor/log4fix/finder"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Usage = "Log 4 Shell fix"
	app.Version = "4.0.1"

	app.Commands = []cli.Command{

		{
			Name:  "detect",
			Usage: "Scan compressed file for log4j vulnerability",
			Action: func(c *cli.Context) {
				finder.LoggerInit()
				if len(c.Args()) == 0 {
					finder.ErrorLogger.Fatalf("Please specify path to file as first argument.")
				}
				warPath := c.Args()[0]

				if len(warPath) > 0 {
					hasLog4Jar, isVuln, path, err := finder.ArchiveVulnerableLog4shell(warPath)
					if err != nil {
						finder.ErrorLogger.Fatalf("%v\n", err)
					}

					if hasLog4Jar {
						if isVuln {
							finder.InfoLogger.Println("Log4 jar file found - Vulnerable - has JndiLookup.class")
							finder.InfoLogger.Printf("Path to vulnerable class: %s\n", path)
						} else {
							finder.InfoLogger.Printf("Log4 jar file found - NOT Vulnerable - missing class\n")
						}
					} else {
						finder.InfoLogger.Printf("Not vulnerable\n")
					}
				} else {
					finder.InfoLogger.Printf("Please give path to file as first argument.")
				}
			},
		},
		{
			Name:  "fix",
			Usage: "Scan compressed file for log4j vulnerability and delete the vulnerable class. Note, this command overwrites the given file.",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "overwrite",
					Usage: "This flag is necessary to give permission to overwrite the file.",
				},
			},
			Action: func(c *cli.Context) {
				finder.LoggerInit()
				if len(c.Args()) == 0 {
					finder.ErrorLogger.Fatalf("Please specify path to file as first argument.")
				}
				warPath := c.Args()[0]

				if len(warPath) > 0 {
					if !c.Bool("overwrite") {
						finder.WarningLogger.Fatalf("This command overwrites the given file. Please give overwrite permission by setting flag --overwrite")
						return
					}

					hasLog4Jar, isVuln, path, err := finder.ArchiveVulnerableLog4shell(warPath)
					if err != nil {
						finder.ErrorLogger.Fatalf("%v\n", err)
					}

					if hasLog4Jar {
						if isVuln {
							finder.InfoLogger.Println("Log4 jar file found - Vulnerable - has JndiLookup.class")

							finder.FixFile(warPath, []string{path})

						} else {
							finder.InfoLogger.Printf("Log4 jar file found - NOT Vulnerable - missing class\n")
						}
					} else {
						finder.InfoLogger.Printf("Not vulnerable\n")
					}
				} else {
					finder.InfoLogger.Printf("Please give path to file as first argument.")
				}
			},
		},
		{
			Name:  "scan",
			Usage: "Scan file system for log4j vulnerability.",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "fix",
					Usage: "If this flag is present the command scans the directory and removes all instances of the vulnerable class.",
				},
				&cli.StringFlag{
					Name:  "output",
					Usage: "Write the path to the vulnerable files into the given file.",
				},
			},
			Action: func(c *cli.Context) {
				finder.LoggerInit()
				if len(c.Args()) == 0 {
					finder.ErrorLogger.Fatalf("Please specify path to directory as first argument.")
				}
				rootDir := c.Args()[0]
				finder.InfoLogger.Printf("scanning...\n")
				paths, err := finder.Scan(rootDir)
				if err != nil {
					finder.ErrorLogger.Fatalf("%v\n", err)
				}

				finder.InfoLogger.Printf("Number of war/jar/ear files found: %d\n", len(paths))

				vulnFiles := []string{}
				for _, path := range paths {
					finder.InfoLogger.Printf("Scanning %s for log4j\n", path)
					hasLog4Jar, isVuln, vulnPath, err := finder.ArchiveVulnerableLog4shell(path)
					if err != nil {
						finder.ErrorLogger.Printf("err: %v\n", err)
						continue
					}

					if hasLog4Jar {
						if isVuln {
							finder.InfoLogger.Printf("Log4 jar file found - Vulnerable - has JndiLookup.class\n")
							vulnFiles = append(vulnFiles, path)

							if c.Bool("fix") {
								finder.FixFile(path, []string{vulnPath})
							}

						} else {
							finder.InfoLogger.Printf("Log4 jar file found - NOT Vulnerable - missing JndiLookup.class\n")
						}
					} else {
						finder.InfoLogger.Printf("Not vulnerable\n")
					}

					fmt.Println()
				}

				finder.InfoLogger.Printf("Number of war/jar/ear files containing log4j vulnerability: %d\n", len(vulnFiles))

				fmt.Println()

				if len(vulnFiles) > 0 && !c.Bool("fix") {
					finder.InfoLogger.Println("Run the following to fix the files:")

					var f *os.File
					if c.IsSet("output") {
						var err error
						f, err = os.Create(c.String("output"))
						if err != nil {
							finder.ErrorLogger.Printf("%v\n", err)
						} else {
							defer f.Close()
						}
					}

					for _, filepath := range vulnFiles {
						fmt.Printf("\t log4fix fix %s --overwrite\n", filepath)

						if f != nil {
							f.WriteString(filepath + "\n")
						}
					}

					finder.InfoLogger.Println("Or run this command with flag --fix")
				}

			},
		},
	}

	app.Run(os.Args)
}
