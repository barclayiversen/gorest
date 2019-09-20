package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"gorest/driver"
	"gorest/models"

	"github.com/davecgh/go-spew/spew"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

func init() {
	godotenv.Load()
}

func main() {
	db = driver.ConnectDB()

	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleware(protectedEndpoint))

	log.Println("Listening on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))
}

func respondWithError(w http.ResponseWriter, status int, message string) {
	var error models.Error
	error.Message = message
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

func responseJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user models.User

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is missing")
		return
	}

	if user.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is missing")
		return
	}
	spew.Dump(user)

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

	if err != nil {
		log.Fatal(err)
	}

	user.Password = string(hash)

	stmt := "INSERT INTO USERS (email,password) VALUES ($1, $2) RETURNING id"

	db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Server error.")
		return
	}

	user.Password = ""

	w.Header().Set("Content-Type", "application/json")

	responseJSON(w, user)
}

func GenerateToken(user models.User) (string, error) {
	var err error
	secret := os.Getenv("JWT_SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})

	tokenString, err := token.SignedString([]byte(secret))

	if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	var jwt models.JWT

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is missing")
		return
	}

	if user.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is missing")
		return
	}
	//Save plaintext password in variable for comparing to hash later
	password := user.Password

	row := db.QueryRow("SELECT * FROM users WHERE email = $1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusBadRequest, "The User does not exist")
			return
		} else {
			log.Fatal(err)
		}
	}

	hashedPassword := user.Password

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid Password")
		return
	}

	token, err := GenerateToken(user)

	if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token
	responseJSON(w, jwt)

}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("\"yes\""))
	fmt.Println("protected endpoint invoked")
}

func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject models.Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}

				return []byte(os.Getenv("JWT_SECRET")), nil
			})

			if error != nil {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, error.Error())
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, error.Error())
				return
			}
		} else {
			errorObject.Message = "Invalid Token"
			respondWithError(w, http.StatusUnauthorized, "Invalid Token")
			return
		}
	})
}
