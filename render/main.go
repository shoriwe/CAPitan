package main

import (
	"github.com/shoriwe/CAPitan/data/noauth"
	"github.com/shoriwe/CAPitan/logs"
	"github.com/shoriwe/CAPitan/web"
	"log"
	"net/http"
	"os"
)

func main() {
	dataController := noauth.NewNoAuthDB()
	logger := logs.NewLogger(os.Stderr)
	handler := web.NewServerMux(dataController, logger)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", handler))
}
