package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/nanitor/log4fix/finder"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Usage = "Log 4 Shell fix"
	app.Version = "0.0.0"

	app.Commands = []cli.Command{

		{
			Name:  "detect",
			Usage: "Scan file system for log4j vulnerability",
			Action: func(c *cli.Context) {
				finder.LoggerInit()
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
			Usage: "Scan file system for log4j vulnerability and delete the vulnerable class. Note, this command overwrites the given file.",
			Action: func(c *cli.Context) {
				finder.LoggerInit()
				warPath := c.Args()[0]

				if len(warPath) > 0 {
					fmt.Print("This action overwrites the file. Are you sure? [y/n]: ")
					var input string
					fmt.Scanln(&input)

					if strings.ToLower(input) != "y" {
						fmt.Println("quitting...")
						return
					}

					hasLog4Jar, isVuln, path, err := finder.ArchiveVulnerableLog4shell(warPath)
					if err != nil {
						finder.ErrorLogger.Fatalf("%v\n", err)
					}

					if hasLog4Jar {
						if isVuln {
							finder.InfoLogger.Println("Log4 jar file found - Vulnerable - has JndiLookup.class")
							finder.InfoLogger.Printf("Class to be deleted: %s\n", path)
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
	}

	app.Run(os.Args)
}
