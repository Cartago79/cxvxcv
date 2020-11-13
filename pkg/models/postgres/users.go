package postgres

import (
	"context"
	"database/sql"
	"errors"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/yerdosikosan/finalProject/pkg/models"
	"golang.org/x/crypto/bcrypt"
	"time"
)

const(
	insertUsers = "INSERT INTO users (name, email, hashed_password, created) VALUES($1,$2,$3,$4) RETURNING id"
	getUsers = "SELECT id, hashed_password FROM users WHERE email = $1 AND active = TRUE"
)
type UserModel struct {
	Pool *pgxpool.Pool
}


func (m *UserModel) Insert(name, email, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}

	var id uint64

	row := m.Pool.QueryRow(context.Background(),insertUsers,name,email,hashedPassword,time.Now())
	err = row.Scan(&id)
	if err != nil {

		return err
	}
	return nil
}


func (m *UserModel) Authenticate(email, password string) (int, error) {
	var id uint64
	var hashedPassword []byte

	row := m.Pool.QueryRow(context.Background(), getUsers, email)
	err := row.Scan(&id, &hashedPassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, models.ErrInvalidCredentials
		} else {
			return 0, err
		}
	}

	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil{
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword){
			return 0, models.ErrInvalidCredentials
		}else{
			return 0, err
		}
	}

	return int(id), nil
}


func (m *UserModel) Get(id int) (*models.User, error) {
	return nil, nil
}

