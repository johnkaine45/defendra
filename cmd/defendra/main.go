package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/johnkaine/defendra/internal/app"
	"github.com/johnkaine/defendra/internal/ui"
)

func main() {
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		os.Stderr.WriteString("\n" + ui.Interrupted())
		os.Exit(2)
	}()
	os.Exit(app.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
