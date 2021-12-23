package finder

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/apoorvam/goterminal"
)

var (
	WarningLogger *log.Logger
	InfoLogger    *log.Logger
	ErrorLogger   *log.Logger
)

func LoggerInit() {
	InfoLogger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	WarningLogger = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = log.New(os.Stdout, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	IOLogger = LiveLogger{}
}
func Silent() {
	InfoLogger.SetFlags(0)
	InfoLogger.SetOutput(ioutil.Discard)

	ErrorLogger.SetFlags(0)
	ErrorLogger.SetOutput(ioutil.Discard)

	WarningLogger.SetFlags(0)
	WarningLogger.SetOutput(ioutil.Discard)
}

type LiveLogger struct {
	*goterminal.Writer
}

var IOLogger LiveLogger

var TextChan chan string

func (l *LiveLogger) Init() {
	TextChan = make(chan string)
	l.Writer = goterminal.New(os.Stdout)
}

func (l *LiveLogger) Close() {
	if l.Writer != nil {
		l.Writer.Reset()
	}

}

func (l *LiveLogger) Printf(text string, args ...interface{}) {
	if l.Writer == nil {
		l.Init()
	}
	l.Writer.Clear()
	fmt.Fprintf(l.Writer, text, args...)
	l.Writer.Print()
}

func (l *LiveLogger) Println(text string) {
	if l.Writer == nil {
		l.Init()
	}
	l.Writer.Clear()
	fmt.Fprintln(l.Writer, text)
	l.Writer.Print()
}
