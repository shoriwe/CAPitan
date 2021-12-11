package main

import (
	"flag"
	"fmt"
	"github.com/shoriwe/CAPitan/internal/data/memory"
	"github.com/shoriwe/CAPitan/internal/logs"
	"github.com/shoriwe/CAPitan/internal/web"
	"log"
	"net/http"
	"os"
)

func printError(err error) {
	_, _ = fmt.Fprintf(os.Stderr, err.Error())
	os.Exit(1)
}

func generalHelp() {
	result := ""
	result += os.Args[0] + " COMMAND [ARGS]\n"
	result += `Commands available:
- memory        Run in memory mode
- database      Run in database mode
- help          Show this help`
	_, _ = fmt.Fprintf(os.Stderr, result)
}

func handleMemoryCommand() {
	var host string = "127.0.0.1:8080"
	if len(os.Args) > 2 {
		flagSet := flag.NewFlagSet("memory", flag.ExitOnError)
		flagSet.StringVar(&host, "host", "127.0.0.1:8080", "Host to listen on")
		parseError := flagSet.Parse(os.Args[2:])
		if parseError != nil {
			printError(parseError)
		}
	}
	dataController := memory.NewInMemoryDB()
	logger := logs.NewLogger(os.Stderr)
	handler := web.NewServerMux(dataController, logger)
	log.Fatal(http.ListenAndServe(host, handler))
}

func main() {
	if len(os.Args) == 1 {
		generalHelp()
		return
	}
	command := os.Args[1]
	switch command {
	case "memory":
		handleMemoryCommand()
	case "database":
		break
	case "help":
		generalHelp()
	default:
		generalHelp()
	}
}
