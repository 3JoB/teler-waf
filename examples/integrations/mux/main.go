package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/3JoB/teler-waf"
	"github.com/gorilla/mux"
)

func main() {
	telerMiddleware := teler.New()

	r := mux.NewRouter()
	r.Use(telerMiddleware.Handler)
	http.Handle("/", r)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", 8080), nil))
}
