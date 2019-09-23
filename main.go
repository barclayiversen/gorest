package main

import (
	"database/sql"
	"log"
	"net/http"

	"gorest/controllers"
	"gorest/driver"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

var db *sql.DB

func init() {
	godotenv.Load()
}

func main() {
	db = driver.ConnectDB()
	controller := controllers.Controller{}
	router := mux.NewRouter()
	router.HandleFunc("/signup", controller.Signup(db)).Methods("POST")
	router.HandleFunc("/login", controller.Login(db)).Methods("POST")
	router.HandleFunc("/protected", controller.TokenVerifyMiddleware(controller.ProtectedEndpoint()))

	log.Println("Listening on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))
}
