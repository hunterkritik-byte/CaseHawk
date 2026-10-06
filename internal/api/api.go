package api

import (
    "crypto/sha256"
    "database/sql"
    "encoding/hex"
    "encoding/json"
    "io"
    "net/http"
    "os"
    "path/filepath"
    "strings"

    "github.com/google/uuid"
)

type Server struct { db *sql.DB; dataDir string }

func New(db *sql.DB, dataDir, apiToken string) http.Handler {
    s := &Server{db: db, dataDir: dataDir}
    mux := http.NewServeMux()
    mux.HandleFunc("GET /healthz", s.health)
    mux.HandleFunc("POST /api/v1/auth/login", s.login)
    mux.Handle("POST /api/v1/cases", requireAuth(http.HandlerFunc(s.createCase), "investigator"))
    mux.Handle("GET /api/v1/cases", requireAuth(http.HandlerFunc(s.listCases), "viewer"))
    mux.Handle("POST /api/v1/cases/{id}/evidence", requireAuth(http.HandlerFunc(s.uploadEvidence), "investigator", "evidence_officer"))
    mux.Handle("GET /api/v1/cases/{id}/evidence", requireAuth(http.HandlerFunc(s.listEvidence), "viewer"))
    mux.Handle("GET /api/v1/cases/{id}/timeline", requireAuth(http.HandlerFunc(s.timeline), "viewer"))
    mux.HandleFunc("GET /dashboard", s.dashboard)
    return withServer(s, mux)
}

func withAuth(next http.Handler, token string) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/healthz" { next.ServeHTTP(w,r); return }
        if token == "" { writeError(w, 503, "CASEHAWK_API_TOKEN is not configured"); return }
        auth := strings.TrimSpace(r.Header.Get("Authorization"))
        if auth != "Bearer "+token { writeError(w, 401, "unauthorized"); return }
        next.ServeHTTP(w,r)
    })
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status":"ok","service":"casehawk"}) }

type createCaseRequest struct {
    CaseNumber string `json:"case_number"`
    Title string `json:"title"`
    Description string `json:"description"`
}

func (s *Server) createCase(w http.ResponseWriter, r *http.Request) {
    var req createCaseRequest
    if json.NewDecoder(r.Body).Decode(&req) != nil { writeError(w,400,"invalid JSON"); return }
    req.CaseNumber = strings.TrimSpace(req.CaseNumber); req.Title = strings.TrimSpace(req.Title)
    if req.CaseNumber == "" || req.Title == "" { writeError(w,400,"case_number and title are required"); return }
    id := uuid.New()
    _, err := s.db.ExecContext(r.Context(), "INSERT INTO cases (id,case_number,title,description) VALUES ($1,$2,$3,$4)", id,req.CaseNumber,req.Title,req.Description)
    if err != nil { writeError(w,409,"could not create case"); return }
    s.audit(r,id,"case.created",actor(r),id.String())
    writeJSON(w,201,map[string]any{"id":id,"case_number":req.CaseNumber,"title":req.Title,"description":req.Description,"status":"open"})
}

func (s *Server) listCases(w http.ResponseWriter, r *http.Request) {
    rows, err := s.db.QueryContext(r.Context(), "SELECT id,case_number,title,description,status,created_at FROM cases ORDER BY created_at DESC")
    if err != nil { writeError(w,500,"database error"); return }; defer rows.Close()
    var out []map[string]any
    for rows.Next() {
        var id,number,title,description,status string; var created any
        if err := rows.Scan(&id,&number,&title,&description,&status,&created); err != nil { writeError(w,500,"database error"); return }
        out = append(out,map[string]any{"id":id,"case_number":number,"title":title,"description":description,"status":status,"created_at":created})
    }
    writeJSON(w,200,out)
}

func (s *Server) uploadEvidence(w http.ResponseWriter, r *http.Request) {
    caseID, err := uuid.Parse(r.PathValue("id")); if err != nil { writeError(w,400,"invalid case id"); return }
    if r.ContentLength > 100*1024*1024 { writeError(w,413,"evidence exceeds 100 MB limit"); return }
    if err := r.ParseMultipartForm(8<<20); err != nil { writeError(w,400,"multipart form required"); return }
    file, header, err := r.FormFile("file"); if err != nil { writeError(w,400,"file field is required"); return }; defer file.Close()
    dir := filepath.Join(s.dataDir,caseID.String()); if err := os.MkdirAll(dir,0700); err != nil { writeError(w,500,"storage error"); return }
    id := uuid.New(); path := filepath.Join(dir,id.String())
    out, err := os.OpenFile(path,os.O_CREATE|os.O_WRONLY|os.O_EXCL,0600); if err != nil { writeError(w,500,"could not create evidence object"); return }; defer out.Close()
    h := sha256.New(); n, err := io.Copy(io.MultiWriter(out,h),io.LimitReader(file,100*1024*1024+1))
    if err != nil || n > 100*1024*1024 { _=os.Remove(path); writeError(w,413,"evidence exceeds 100 MB limit"); return }
    sum := hex.EncodeToString(h.Sum(nil)); contentType := header.Header.Get("Content-Type"); if contentType=="" { contentType="application/octet-stream" }
    _, err = s.db.ExecContext(r.Context(),"INSERT INTO evidence (id,case_id,filename,content_type,size_bytes,sha256,storage_path) VALUES ($1,$2,$3,$4,$5,$6,$7)",id,caseID,filepath.Base(header.Filename),contentType,n,sum,path)
    if err != nil { _=os.Remove(path); writeError(w,500,"database error"); return }
    s.audit(r,caseID,"evidence.uploaded",actor(r),id.String())
    writeJSON(w,201,map[string]any{"id":id,"case_id":caseID,"filename":filepath.Base(header.Filename),"content_type":contentType,"size_bytes":n,"sha256":sum})
}

func (s *Server) timeline(w http.ResponseWriter,r *http.Request){
    caseID,err:=uuid.Parse(r.PathValue("id"));if err!=nil{writeError(w,400,"invalid case id");return}
    rows,err:=s.db.QueryContext(r.Context(),`SELECT created_at, action, actor, target_id, metadata FROM audit_events WHERE case_id=$1 ORDER BY created_at ASC`,caseID)
    if err!=nil{writeError(w,500,"database error");return};defer rows.Close()
    var out []map[string]any
    for rows.Next(){var at any;var action,actor,target string;var meta []byte;if err:=rows.Scan(&at,&action,&actor,&target,&meta);err!=nil{writeError(w,500,"database error");return};var m any=map[string]any{};_ = json.Unmarshal(meta,&m);out=append(out,map[string]any{"at":at,"action":action,"actor":actor,"target_id":target,"metadata":m})}
    writeJSON(w,200,out)
}

func (s *Server) listEvidence(w http.ResponseWriter, r *http.Request) {
    caseID, err := uuid.Parse(r.PathValue("id")); if err != nil { writeError(w,400,"invalid case id"); return }
    rows, err := s.db.QueryContext(r.Context(),"SELECT id,filename,content_type,size_bytes,sha256,created_at FROM evidence WHERE case_id=$1 ORDER BY created_at DESC",caseID)
    if err != nil { writeError(w,500,"database error"); return }; defer rows.Close()
    var out []map[string]any
    for rows.Next() { var id,filename,ct,sum string; var size int64; var created any; if err:=rows.Scan(&id,&filename,&ct,&size,&sum,&created); err!=nil { writeError(w,500,"database error"); return }; out=append(out,map[string]any{"id":id,"filename":filename,"content_type":ct,"size_bytes":size,"sha256":sum,"created_at":created}) }
    writeJSON(w,200,out)
}

func (s *Server) audit(r *http.Request, caseID uuid.UUID, action, who, target string) { _,_=s.db.ExecContext(r.Context(),"INSERT INTO audit_events (case_id,action,actor,target_id) VALUES ($1,$2,$3,$4)",caseID,action,who,target) }
func actor(r *http.Request) string { if v:=strings.TrimSpace(r.Header.Get("X-CaseHawk-Actor")); v!="" { return v }; return "system" }
func writeJSON(w http.ResponseWriter,status int,v any) { w.Header().Set("Content-Type","application/json"); w.WriteHeader(status); _=json.NewEncoder(w).Encode(v) }
func writeError(w http.ResponseWriter,status int,msg string) { writeJSON(w,status,map[string]string{"error":msg}) }
