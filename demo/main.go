package main

import (
	"github.com/shoriwe/CAPitan/data/memory"
	"github.com/shoriwe/CAPitan/logs"
	"github.com/shoriwe/CAPitan/web"
	"log"
	"net/http"
	"os"
)

func main() {
	dataController := memory.NewInMemoryDB()
	logger := logs.NewLogger(os.Stderr)
	handler := web.NewServerMux(dataController, logger)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", handler))
}
