package userRepository

import (
	"database/sql"
	"gorest/models"
	"log"
)

type UserRepository struct{}

func logFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func (u UserRepository) Signup(db *sql.DB, user models.User) models.User {
	stmt := "INSERT INTO USERS (email,password) VALUES ($1, $2) RETURNING id;"
	err := db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)

	logFatal(err)

	user.Password = ""
	return user
}

func (u UserRepository) Login(db *sql.DB, user models.User) (models.User, error) {
	// if user.Email == "" {
	// 	utils.RespondWithError(w, http.StatusBadRequest, "Email is missing")
	// 	return
	// }

	// if user.Password == "" {
	// 	utils.RespondWithError(w, http.StatusBadRequest, "Password is missing")
	// 	return
	// }
	//Save plaintext password in variable for comparing to hash later

	row := db.QueryRow("SELECT * FROM users WHERE email = $1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		return user, err
	}

	return user, nil
}
