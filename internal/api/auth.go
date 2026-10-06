package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/hunterkritik-byte/CaseHawk/internal/store"
)

func tokenHash(token string) string { sum:=sha256.Sum256([]byte(token)); return hex.EncodeToString(sum[:]) }

func (s *Server) login(w http.ResponseWriter,r *http.Request){
	var req struct{Username string `json:"username"`; Password string `json:"password"`}
	if json.NewDecoder(r.Body).Decode(&req)!=nil {writeError(w,400,"invalid JSON");return}
	u,err:=store.Authenticate(r.Context(),s.db,req.Username,req.Password);if err!=nil{writeError(w,401,"invalid credentials");return}
	token,err:=store.NewToken();if err!=nil{writeError(w,500,"could not create session");return}
	_,err=s.db.ExecContext(r.Context(),"INSERT INTO sessions (token_hash,user_id,expires_at) VALUES ($1,$2,$3)",tokenHash(token),u.ID,time.Now().Add(8*time.Hour))
	if err!=nil{writeError(w,500,"could not create session");return}
	writeJSON(w,200,map[string]any{"access_token":token,"token_type":"Bearer","expires_in":28800,"user":map[string]any{"id":u.ID,"username":u.Username,"role":u.Role}})
}

func (s *Server) currentUser(r *http.Request)(store.User,bool){
	auth:=strings.TrimSpace(r.Header.Get("Authorization"));if !strings.HasPrefix(auth,"Bearer "){return store.User{},false}
	token:=strings.TrimSpace(strings.TrimPrefix(auth,"Bearer "));if token==""{return store.User{},false}
	var u store.User
	err:=s.db.QueryRowContext(r.Context(),`SELECT u.id,u.username,u.role,u.active FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=$1 AND s.expires_at>now()`,tokenHash(token)).Scan(&u.ID,&u.Username,&u.Role,&u.Active)
	return u,err==nil&&u.Active
}

type serverKey struct{}
func withServer(s *Server,next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){next.ServeHTTP(w,r.WithContext(context.WithValue(r.Context(),serverKey{},s)))})}

func requireAuth(next http.Handler, roles ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		s,ok:=r.Context().Value(serverKey{}).(*Server);if !ok{writeError(w,500,"server context missing");return}
		u,ok:=s.currentUser(r);if !ok{writeError(w,401,"authentication required");return}
		if len(roles)>0 {allowed:=false;for _,role:=range roles{if u.Role==role||u.Role=="admin"{allowed=true;break}};if !allowed{writeError(w,403,"insufficient permissions");return}}
		next.ServeHTTP(w,r)
	})
}

var _ *sql.DB
