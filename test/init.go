package test

import (
	"github.com/shoriwe/CAPitan/internal/data/memory"
	"github.com/shoriwe/CAPitan/internal/logs"
	"github.com/shoriwe/CAPitan/internal/web"
	"net/http/httptest"
	"os"
)

func NewTestServer() *httptest.Server {
	database := memory.NewInMemoryDB()
	logger := logs.NewLogger(os.Stderr)
	handler := web.NewServerMux(database, logger)
	return httptest.NewServer(handler)
}
