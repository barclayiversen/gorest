package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"gorest/models"

	//userRepository
	"gorest/repository/userRepository"
	"gorest/utils"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

func (c Controller) Test() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		utils.ResponseJSON(w, "testing")
	}
}

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

		userRepo := userRepository.UserRepository{}
		user = userRepo.Signup(db, user)

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

		password := user.Password

		userRepo := userRepository.UserRepository{}
		user, err := userRepo.Login(db, user)

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
