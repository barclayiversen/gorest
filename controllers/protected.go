package controllers

import (
	"fmt"
	"net/http"
)

type Controller struct{}

func (c Controller) ProtectedEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("\"yes\""))
		fmt.Println("protected endpoint invoked")
	}
}
