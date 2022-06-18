package main

import (
	"fmt"
	"log"
	"net/http"
)

const webPort = "4800"

type Config struct{}

func main() {
	app := Config{}

	log.Printf("Starting a broker service on port %s", webPort)

	// define http server
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", webPort),
		Handler: app.routes(),
	}

	// start server
	err := srv.ListenAndServe()
	if err != nil {
		log.Panic(err)
	}

}
