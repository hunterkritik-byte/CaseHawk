package store

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

type User struct {
	ID uuid.UUID
	Username string
	Role string
	Active bool
}

func HashPassword(password string) ([]byte, []byte, error) {
	if password == "" { return nil,nil,errors.New("password required") }
	salt:=make([]byte,16); if _,err:=rand.Read(salt);err!=nil{return nil,nil,err}
	hash:=argon2.IDKey([]byte(password),salt,3,64*1024,2,32)
	return hash,salt,nil
}

func CreateUser(db *sql.DB, username,password,role string)(User,error){
	username=strings.TrimSpace(username)
	switch role {case "admin","investigator","evidence_officer","viewer":default:return User{},errors.New("invalid role")}
	hash,salt,err:=HashPassword(password);if err!=nil{return User{},err}
	id:=uuid.New()
	_,err=db.Exec("INSERT INTO users (id,username,password_hash,password_salt,role,active) VALUES ($1,$2,$3,$4,$5,true)",id,username,hash,salt,role)
	return User{ID:id,Username:username,Role:role,Active:true},err
}

func Authenticate(ctx context.Context,db *sql.DB,username,password string)(User,error){
	var u User;var hash,salt []byte
	err:=db.QueryRowContext(ctx,"SELECT id,username,password_hash,password_salt,role,active FROM users WHERE username=$1",username).Scan(&u.ID,&u.Username,&hash,&salt,&u.Role,&u.Active)
	if err!=nil||!u.Active{return User{},errors.New("invalid credentials")}
	got:=argon2.IDKey([]byte(password),salt,3,64*1024,2,32)
	if subtle.ConstantTimeCompare(got,hash)!=1{return User{},errors.New("invalid credentials")}
	return u,nil
}

func NewToken()(string,error){b:=make([]byte,32);if _,err:=rand.Read(b);err!=nil{return "",err};return base64.RawURLEncoding.EncodeToString(b),nil}

func SaveSession(ctx context.Context,db *sql.DB,userID uuid.UUID,token string,expires time.Time) error {
	_,err:=db.ExecContext(ctx,"INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (sha256($1),$2,$3)",token,userID,expires)
	return err
}
