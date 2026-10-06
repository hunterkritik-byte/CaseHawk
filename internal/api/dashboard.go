package api

import "net/http"

func (s *Server) dashboard(w http.ResponseWriter, _ *http.Request) {
 w.Header().Set("Content-Type", "text/html; charset=utf-8")
 _, _ = w.Write([]byte(dashboardHTML))
}

const dashboardHTML = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CaseHawk Investigator Dashboard</title>
<style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:auto;padding:24px;background:#f5f7fb;color:#172033}.card{background:#fff;border:1px solid #dfe4ee;border-radius:12px;padding:18px;margin:12px 0}input,button{padding:10px;border-radius:8px;border:1px solid #ccd3df;margin:4px}button{cursor:pointer}.hidden{display:none}.case{cursor:pointer}.event{padding:10px;border-left:3px solid #5b6cff;margin:8px 0;background:#f8f9fd}small{color:#687386}</style></head>
<body><h1>🚔 CaseHawk</h1><p>Investigator dashboard</p>
<section id="login" class="card"><h2>Sign in</h2><input id="user" placeholder="Username"><input id="pass" type="password" placeholder="Password"><button onclick="login()">Sign in</button><p id="err"></p></section>
<section id="app" class="hidden"><div class="card"><button onclick="openNewCase()">➕ New case</button><button onclick="loadCases()">🔄 Refresh cases</button><button onclick="logout()">🚪 Sign out</button><span id="me"></span></div><div id="cases"></div><div id="workspace"></div><div id="timeline"></div></section>
<script>
let token=sessionStorage.getItem("casehawk_token");const $=id=>document.getElementById(id);
function showApp(){ $("login").classList.toggle("hidden",!!token);$("app").classList.toggle("hidden",!token);if(token)loadCases();}
async function login(){const r=await fetch("/api/v1/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:$("user").value,password:$("pass").value})});const d=await r.json();if(!r.ok){$("err").textContent=d.error||"Login failed";return}token=d.access_token;sessionStorage.setItem("casehawk_token",token);$("me").textContent=d.user.username+" ("+d.user.role+")";showApp()}
function logout(){token=null;sessionStorage.removeItem("casehawk_token");showApp()}
async function api(path){const r=await fetch(path,{headers:{Authorization:"Bearer "+token}});if(r.status===401){logout();throw new Error("session expired")}return r.json()}
async function loadCases(){const data=await api("/api/v1/cases");$("cases").innerHTML="<h2>Cases</h2>"+(data||[]).map(c=>"<div class='card case' onclick=\"loadTimeline('"+c.id+"')\"><b>"+c.case_number+"</b> — "+c.title+"<br><small>"+c.status+"</small></div>").join("")}
async function loadTimeline(id){const data=await api("/api/v1/cases/"+id+"/timeline");$("timeline").innerHTML="<div class='card'><h2>Evidence timeline</h2>"+(data||[]).map(e=>"<div class='event'><b>"+e.action+"</b><br><small>"+e.at+" · "+e.actor+" · "+e.target_id+"</small></div>").join("")+"</div>"}
showApp();</script></body></html>`
