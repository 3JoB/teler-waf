package main

import (
	"net/http"

	"github.com/3JoB/teler-waf"
	"github.com/go-chi/chi"
)

func main() {
	telerMiddleware := teler.New()

	r := chi.NewRouter()
	r.Use(telerMiddleware.Handler)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	})

	http.ListenAndServe("127.0.0.1:3000", r)
}
