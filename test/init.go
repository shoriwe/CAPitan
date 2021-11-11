package test

import (
	"github.com/shoriwe/CAPitan/data/memory"
	"github.com/shoriwe/CAPitan/logs"
	"github.com/shoriwe/CAPitan/web"
	"net/http/httptest"
	"os"
)

func NewTestServer() *httptest.Server {
	database := memory.NewInMemoryDB()
	logger := logs.NewLogger(os.Stderr)
	handler := web.NewServerMux(database, logger)
	return httptest.NewServer(handler)
}
