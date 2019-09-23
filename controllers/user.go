package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"gorest/models"
	"gorest/utils"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

func (c Controller) Signup(db *sql.DB) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User

		json.NewDecoder(r.Body).Decode(&user)

		if user.Email == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Email is missing")
			return
		}

		if user.Password == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Password is missing")
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

		if err != nil {
			log.Fatal(err)
		}

		user.Password = string(hash)

		stmt := "INSERT INTO USERS (email,password) VALUES ($1, $2) RETURNING id"

		db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)

		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Server error.")
			return
		}

		user.Password = ""
		utils.ResponseJSON(w, user)
	}

}

func (c Controller) Login(db *sql.DB) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		var jwt models.JWT

		json.NewDecoder(r.Body).Decode(&user)

		if user.Email == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Email is missing")
			return
		}

		if user.Password == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Password is missing")
			return
		}
		//Save plaintext password in variable for comparing to hash later
		password := user.Password

		row := db.QueryRow("SELECT * FROM users WHERE email = $1", user.Email)
		err := row.Scan(&user.ID, &user.Email, &user.Password)

		hashedPassword := user.Password

		if err != nil {
			if err == sql.ErrNoRows {
				utils.RespondWithError(w, http.StatusBadRequest, "The User does not exist")
				return
			} else {
				log.Fatal(err)
			}
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "Invalid Password")
			return
		}

		token, err := utils.GenerateToken(user)

		if err != nil {
			log.Fatal(err)
		}

		w.WriteHeader(http.StatusOK)
		jwt.Token = token
		utils.ResponseJSON(w, jwt)

	}
}

func (c Controller) TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
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
				utils.RespondWithError(w, http.StatusUnauthorized, error.Error())
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, error.Error())
				return
			}
		} else {
			errorObject.Message = "Invalid Token"
			utils.RespondWithError(w, http.StatusUnauthorized, "Invalid Token")
			return
		}
	})
}
