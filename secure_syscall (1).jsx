import { useState, useEffect, useRef } from "react";

const USERS = {
  admin:   { pw: "admin123",  role: "Admin" },
  dev:     { pw: "dev123",    role: "Developer" },
  auditor: { pw: "audit123",  role: "Auditor" },
};

const ALLOWED = {
  Admin:     null,
  Developer: ["open","read","write","close","socket","connect","send","recv","fork","waitpid"],
  Auditor:   [],
};

const SYSCALL_DB = [
  { id:"open",     name:"open()",     cat:"File I/O",  risk:"Low",      icon:"📄", desc:"Open a file and get back a handle to read or write it", args:[{n:"pathname",t:"text",p:"/path/to/file",help:"Path to the file"},{n:"flags",t:"sel",opts:["O_RDONLY","O_WRONLY","O_RDWR","O_CREAT|O_TRUNC"],help:"How to open it"}] },
  { id:"read",     name:"read()",     cat:"File I/O",  risk:"Low",      icon:"📖", desc:"Read bytes of data from an open file", args:[{n:"fd",t:"num",p:"3",help:"File handle from open()"},{n:"count",t:"num",p:"1024",help:"How many bytes to read"}] },
  { id:"write",    name:"write()",    cat:"File I/O",  risk:"Low",      icon:"✏️",  desc:"Write data into an open file", args:[{n:"fd",t:"num",p:"1",help:"File handle to write to"},{n:"buf",t:"text",p:"hello world",help:"Data to write"},{n:"count",t:"num",p:"11",help:"How many bytes"}] },
  { id:"close",    name:"close()",    cat:"File I/O",  risk:"Low",      icon:"🔒", desc:"Close a file when you are done with it", args:[{n:"fd",t:"num",p:"3",help:"File handle to close"}] },
  { id:"unlink",   name:"unlink()",   cat:"File I/O",  risk:"Medium",   icon:"🗑️",  desc:"Permanently delete a file from disk", args:[{n:"pathname",t:"text",p:"/tmp/tempfile.txt",help:"Full path to the file"}] },
  { id:"fork",     name:"fork()",     cat:"Process",   risk:"Medium",   icon:"🌿", desc:"Spawn a copy of the current process as a child", args:[] },
  { id:"execve",   name:"execve()",   cat:"Process",   risk:"High",     icon:"▶️",  desc:"Run a program, replacing the current process", args:[{n:"filename",t:"text",p:"/bin/ls",help:"Path to the program"},{n:"argv",t:"text",p:"-la /tmp",help:"Arguments to pass"}] },
  { id:"kill",     name:"kill()",     cat:"Process",   risk:"High",     icon:"⚡", desc:"Send a signal (like terminate) to another process", args:[{n:"pid",t:"num",p:"1234",help:"Process ID to signal"},{n:"sig",t:"sel",opts:["SIGTERM","SIGKILL","SIGINT","SIGHUP","SIGUSR1"],help:"Signal type"}] },
  { id:"waitpid",  name:"waitpid()",  cat:"Process",   risk:"Low",      icon:"⏳", desc:"Wait for a child process to finish", args:[{n:"pid",t:"num",p:"-1",help:"PID to wait for (-1 = any child)"},{n:"options",t:"sel",opts:["0","WNOHANG","WUNTRACED"],help:"Wait behavior"}] },
  { id:"socket",   name:"socket()",   cat:"Network",   risk:"Medium",   icon:"🔌", desc:"Create a network connection endpoint", args:[{n:"domain",t:"sel",opts:["AF_INET","AF_INET6","AF_UNIX"],help:"IPv4, IPv6 or Unix"},{n:"type",t:"sel",opts:["SOCK_STREAM","SOCK_DGRAM","SOCK_RAW"],help:"TCP, UDP or raw"}] },
  { id:"bind",     name:"bind()",     cat:"Network",   risk:"High",     icon:"📍", desc:"Assign a port to a socket so others can connect", args:[{n:"sockfd",t:"num",p:"4",help:"Socket handle"},{n:"port",t:"num",p:"8080",help:"Port to listen on"},{n:"addr",t:"text",p:"0.0.0.0",help:"IP to bind (0.0.0.0 = all)"}] },
  { id:"connect",  name:"connect()",  cat:"Network",   risk:"Medium",   icon:"🔗", desc:"Connect your socket to a remote server", args:[{n:"sockfd",t:"num",p:"4",help:"Your socket handle"},{n:"addr",t:"text",p:"192.168.1.100",help:"Server IP address"},{n:"port",t:"num",p:"443",help:"Server port"}] },
  { id:"send",     name:"send()",     cat:"Network",   risk:"Low",      icon:"📤", desc:"Send data over a connected socket", args:[{n:"sockfd",t:"num",p:"4",help:"Connected socket"},{n:"buf",t:"text",p:"GET / HTTP/1.1",help:"Data to send"},{n:"flags",t:"sel",opts:["0","MSG_DONTWAIT","MSG_MORE"],help:"Flags"}] },
  { id:"recv",     name:"recv()",     cat:"Network",   risk:"Low",      icon:"📥", desc:"Receive data from a connected socket", args:[{n:"sockfd",t:"num",p:"4",help:"Connected socket"},{n:"len",t:"num",p:"4096",help:"Max bytes to receive"},{n:"flags",t:"sel",opts:["0","MSG_PEEK","MSG_DONTWAIT"],help:"Flags"}] },
  { id:"mmap",     name:"mmap()",     cat:"Memory",    risk:"High",     icon:"🗺️",  desc:"Map a file or device directly into memory", args:[{n:"addr",t:"text",p:"NULL",help:"Start address (NULL = OS picks)"},{n:"length",t:"num",p:"4096",help:"Bytes to map"},{n:"prot",t:"sel",opts:["PROT_READ","PROT_WRITE","PROT_EXEC","PROT_NONE"],help:"Access permissions"}] },
  { id:"mprotect", name:"mprotect()", cat:"Memory",    risk:"Critical", icon:"🛡️",  desc:"Change the access permissions of a memory region", args:[{n:"addr",t:"text",p:"0x7ffff7fc0000",help:"Start of memory region"},{n:"len",t:"num",p:"4096",help:"Size in bytes"},{n:"prot",t:"sel",opts:["PROT_READ","PROT_WRITE","PROT_EXEC","PROT_NONE"],help:"New permissions"}] },
  { id:"brk",      name:"brk()",      cat:"Memory",    risk:"Medium",   icon:"📏", desc:"Expand or shrink the program heap", args:[{n:"addr",t:"text",p:"NULL",help:"New heap end (NULL = query)"}] },
  { id:"setuid",   name:"setuid()",   cat:"Security",  risk:"Critical", icon:"👤", desc:"Change the user identity of this process", args:[{n:"uid",t:"num",p:"0",help:"User ID (0 = root — very dangerous)"}] },
  { id:"chmod",    name:"chmod()",    cat:"Security",  risk:"High",     icon:"🔑", desc:"Change who can read, write or run a file", args:[{n:"pathname",t:"text",p:"/etc/shadow",help:"File path"},{n:"mode",t:"text",p:"0644",help:"Permission bits e.g. 0644"}] },
  { id:"chroot",   name:"chroot()",   cat:"Security",  risk:"Critical", icon:"🏠", desc:"Change the root directory — creates a filesystem jail", args:[{n:"path",t:"text",p:"/var/chroot",help:"New root directory"}] },
];

const CATS = [
  { id:"File I/O",  icon:"📁", desc:"Read, write & manage files" },
  { id:"Process",   icon:"⚙️",  desc:"Start, stop & manage processes" },
  { id:"Network",   icon:"🌐", desc:"Sockets & connections" },
  { id:"Memory",    icon:"🧠", desc:"Memory mapping & protection" },
  { id:"Security",  icon:"🔐", desc:"Permissions & identity" },
];

const RISK_META = {
  Low:      { color:"#22c55e", bg:"rgba(34,197,94,0.1)",   border:"rgba(34,197,94,0.25)"  },
  Medium:   { color:"#f59e0b", bg:"rgba(245,158,11,0.1)",  border:"rgba(245,158,11,0.25)" },
  High:     { color:"#ef4444", bg:"rgba(239,68,68,0.1)",   border:"rgba(239,68,68,0.25)"  },
  Critical: { color:"#a855f7", bg:"rgba(168,85,247,0.1)",  border:"rgba(168,85,247,0.25)" },
};

const ROLE_META = {
  Admin:     { color:"#fb923c", bg:"rgba(251,146,60,0.15)",  desc:"Full access to all syscalls", badge:"🔴" },
  Developer: { color:"#60a5fa", bg:"rgba(96,165,250,0.15)",  desc:"Safe syscalls only",          badge:"🔵" },
  Auditor:   { color:"#34d399", bg:"rgba(52,211,153,0.15)",  desc:"Read-only — no execution",    badge:"🟢" },
};

let _lid = 200;
function mkLog(user, syscall, args, result) {
  const n = new Date();
  const ts = [n.getHours(),n.getMinutes(),n.getSeconds()].map(x=>x.toString().padStart(2,"0")).join(":");
  const ip = user.role==="Admin"?"10.0.0.1":user.role==="Developer"?"10.0.0.4":"10.0.0.7";
  return { id:++_lid, ts, user:user.username, role:user.role, syscall, args, result, ip };
}

function canRun(role, id) {
  if (role==="Admin") return true;
  if (role==="Auditor") return false;
  return (ALLOWED[role]||[]).includes(id);
}

function fakeResult(sc, args) {
  const m = {
    open:`fd = ${3+Math.floor(Math.random()*20)}  (file opened successfully)`,
    read:`${Math.floor(Math.random()*1024)} bytes read into buffer`,
    write:`${args.count||Math.floor(Math.random()*100)+1} bytes written`,
    close:`0  — file descriptor closed`,
    unlink:`0  — file deleted`,
    fork:`child pid = ${1000+Math.floor(Math.random()*9000)}`,
    execve:`0  — program started`,
    kill:`0  — signal delivered`,
    waitpid:`pid = ${1000+Math.floor(Math.random()*9000)}, exit status = 0`,
    socket:`sockfd = ${4+Math.floor(Math.random()*10)}  (socket created)`,
    bind:`0  — port bound`,
    connect:`0  — connected`,
    send:`${Math.floor(Math.random()*512)+1} bytes sent`,
    recv:`${Math.floor(Math.random()*4096)} bytes received`,
    mmap:`0x${Math.floor(Math.random()*0xffffff).toString(16).padStart(12,"0")}  (mapped)`,
    mprotect:`0  — memory protection updated`,
    brk:`0x${Math.floor(Math.random()*0xfffff).toString(16).padStart(12,"0")}`,
    setuid:`0  — user identity changed to uid ${args.uid||0}`,
    chmod:`0  — permissions set to ${args.mode||"0644"}`,
    chroot:`0  — root changed to ${args.path||"/"}`,
  };
  return m[sc.id]||"0";
}

const SEED_LOGS = [
  { id:1, ts:"08:42:11", user:"admin",   role:"Admin",     syscall:"chmod()",  args:{pathname:"/etc/passwd",mode:"0644"}, result:"success", ip:"10.0.0.1" },
  { id:2, ts:"08:55:03", user:"dev",     role:"Developer", syscall:"mmap()",   args:{addr:"NULL",length:4096,prot:"PROT_EXEC"}, result:"blocked", ip:"10.0.0.4" },
  { id:3, ts:"09:12:44", user:"dev",     role:"Developer", syscall:"read()",   args:{fd:3,count:1024}, result:"success", ip:"10.0.0.4" },
  { id:4, ts:"09:31:22", user:"admin",   role:"Admin",     syscall:"setuid()", args:{uid:0}, result:"success", ip:"10.0.0.1" },
  { id:5, ts:"09:31:25", user:"admin",   role:"Admin",     syscall:"chroot()", args:{path:"/var/chroot"}, result:"success", ip:"10.0.0.1" },
  { id:6, ts:"09:45:00", user:"auditor", role:"Auditor",   syscall:"read()",   args:{fd:5,count:512}, result:"blocked", ip:"10.0.0.7" },
];

const SEED_ALERTS = [
  { id:1, sev:"High",   title:"Privilege escalation pattern detected", detail:"setuid(0) followed by chroot() — admin session 09:31", ts:"09:31:25", dismissed:false },
  { id:2, sev:"Medium", title:"Unauthorized syscall attempt", detail:"dev tried mmap() — not in Developer allowlist", ts:"08:55:03", dismissed:false },
];

export default function App() {
  const [screen,   setScreen]   = useState("login");
  const [user,     setUser]     = useState(null);
  const [sessecs,  setSessecs]  = useState(900);
  const [lf,       setLf]       = useState({ u:"", p:"", err:"", att:0, show:false });
  const [cat,      setCat]      = useState("File I/O");
  const [sc,       setSc]       = useState(null);
  const [argv,     setArgv]     = useState({});
  const [execRes,  setExecRes]  = useState(null);
  const [execSt,   setExecSt]   = useState(null);
  const [logs,     setLogs]     = useState(SEED_LOGS);
  const [alerts,   setAlerts]   = useState(SEED_ALERTS);
  const [logF,     setLogF]     = useState({ res:"all", q:"" });
  const [expanded, setExpanded] = useState(null);
  const [tip,      setTip]      = useState(true);
  const timerRef = useRef(null);

  useEffect(()=>{
    if(screen==="dashboard"){
      timerRef.current=setInterval(()=>setSessecs(s=>{if(s<=1){doLogout();return 0;}return s-1;}),1000);
    }
    return ()=>clearInterval(timerRef.current);
  },[screen]);

  const fmt=s=>`${Math.floor(s/60).toString().padStart(2,"0")}:${(s%60).toString().padStart(2,"0")}`;

  function pushLog(e){
    setLogs(p=>[...p,mkLog(e.user,e.syscall,e.args,e.result)]);
    if(e.blocked) addAlert("Medium","Unauthorized syscall attempt",`${e.user.username} [${e.user.role}] tried ${e.syscall} — not permitted`);
    if(!e.blocked&&["setuid","mprotect","chroot"].includes(e.scId)) addAlert("High","Critical syscall executed",`${e.user.username} ran ${e.syscall} — flagged for review`);
  }

  function addAlert(sev,title,detail){
    const ts=new Date().toLocaleTimeString("en-GB",{hour12:false});
    setAlerts(p=>[...p,{id:Date.now()+Math.random(),sev,title,detail,ts,dismissed:false}]);
  }

  function doLogin(){
    const u=USERS[lf.u.trim().toLowerCase()];
    if(!u||u.pw!==lf.p){
      const att=lf.att+1;
      if(att>=3) addAlert("Critical","Brute force detected",`${att} failed attempts for "${lf.u}"`);
      setLf(f=>({...f,err:`Wrong username or password${att>=2?` (${att} attempts)`:""}`,att}));
      return;
    }
    setUser({username:lf.u.trim().toLowerCase(),role:u.role});
    setScreen("dashboard"); setSessecs(900);
    setLf({u:"",p:"",err:"",att:0,show:false});
  }

  function doLogout(){
    clearInterval(timerRef.current);
    setUser(null); setScreen("login"); setSc(null); setExecRes(null); setExecSt(null);
  }

  function pickSc(s){setSc(s);setArgv({});setExecRes(null);setExecSt(null);}

  function doExec(){
    if(!sc||execSt==="running") return;
    setExecSt("running");
    setTimeout(()=>{
      const ok=canRun(user.role,sc.id);
      if(!ok){
        setExecSt("blocked");
        setExecRes(`Permission denied\n\nYour role (${user.role}) cannot call ${sc.name}.\nOnly Admin accounts can run this syscall.`);
        pushLog({user,syscall:sc.name,args:argv,result:"blocked",blocked:true,scId:sc.id});
      } else {
        setExecSt("success");
        setExecRes(fakeResult(sc,argv));
        pushLog({user,syscall:sc.name,args:argv,result:"success",blocked:false,scId:sc.id});
      }
    },600);
  }

  const fLogs=[...logs].filter(l=>{
    if(user?.role==="Developer"&&l.user!==user.username) return false;
    if(logF.res!=="all"&&l.result!==logF.res) return false;
    if(logF.q&&!l.syscall.toLowerCase().includes(logF.q.toLowerCase())&&!l.user.includes(logF.q.toLowerCase())) return false;
    return true;
  }).reverse();

  const activeAlerts=alerts.filter(a=>!a.dismissed);
  const sessColor=sessecs<120?"#ef4444":sessecs<300?"#f59e0b":"#22c55e";
  const rm=user?ROLE_META[user.role]:null;
  const mono={fontFamily:"'Cascadia Code','Fira Code','Courier New',monospace"};
  const card={background:"#1a1f2e",border:"1px solid #2d3448",borderRadius:12};

  // ─── LOGIN ────────────────────────────────────────────────────────────────
  if(screen==="login") return(
    <div style={{fontFamily:"'Segoe UI',system-ui,sans-serif",background:"#0f1117",color:"#e2e8f0",minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",padding:20}}>
      <style>{`
        @keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
        .fade-up{animation:fadeUp .35s ease}
        .role-card{transition:all .15s ease;cursor:pointer}
        .role-card:hover{transform:translateY(-2px)!important}
        .sign-in-btn:hover{opacity:.88!important}
        .sign-in-btn{transition:opacity .15s}
        input:focus{outline:none!important;border-color:#3b82f6!important;box-shadow:0 0 0 3px rgba(59,130,246,0.2)!important}
      `}</style>
      <div className="fade-up" style={{width:420}}>
        <div style={{textAlign:"center",marginBottom:28}}>
          <div style={{fontSize:44,marginBottom:10}}>🛡️</div>
          <div style={{fontSize:24,fontWeight:700,color:"#f8fafc",letterSpacing:"-0.5px"}}>Syscall Guardian</div>
          <div style={{color:"#64748b",fontSize:13,marginTop:6}}>Secure System Call Interface — v2.4.1</div>
        </div>

        <div style={{marginBottom:18}}>
          <div style={{fontSize:11,color:"#475569",marginBottom:10,textTransform:"uppercase",letterSpacing:"0.08em",fontWeight:600}}>Try a role — click to auto-fill</div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8}}>
            {[["admin","admin123","Admin"],["dev","dev123","Developer"],["auditor","audit123","Auditor"]].map(([u,p,r])=>(
              <div key={u} className="role-card" onClick={()=>setLf(f=>({...f,u,p,err:""}))}
                style={{background:lf.u===u?ROLE_META[r].bg:"#141824",border:`1.5px solid ${lf.u===u?ROLE_META[r].color:"#2d3448"}`,borderRadius:10,padding:"12px 8px",textAlign:"center"}}>
                <div style={{fontSize:20,marginBottom:6}}>{ROLE_META[r].badge}</div>
                <div style={{fontWeight:700,fontSize:13,color:lf.u===u?ROLE_META[r].color:"#94a3b8",marginBottom:3}}>{r}</div>
                <div style={{fontSize:10,color:"#475569",lineHeight:1.4}}>{ROLE_META[r].desc}</div>
              </div>
            ))}
          </div>
        </div>

        <div style={{...card,padding:"22px 24px"}}>
          <div style={{marginBottom:14}}>
            <label style={{display:"block",fontSize:12,color:"#94a3b8",marginBottom:6,fontWeight:500}}>Username</label>
            <input value={lf.u} onChange={e=>setLf(f=>({...f,u:e.target.value,err:""}))} onKeyDown={e=>e.key==="Enter"&&doLogin()} placeholder="Enter username"
              style={{width:"100%",background:"#0f1117",border:"1px solid #2d3448",borderRadius:8,padding:"10px 14px",color:"#f1f5f9",fontSize:14,boxSizing:"border-box",transition:"border .15s,box-shadow .15s"}} />
          </div>
          <div style={{marginBottom:18}}>
            <label style={{display:"block",fontSize:12,color:"#94a3b8",marginBottom:6,fontWeight:500}}>Password</label>
            <div style={{position:"relative"}}>
              <input type={lf.show?"text":"password"} value={lf.p} onChange={e=>setLf(f=>({...f,p:e.target.value,err:""}))} onKeyDown={e=>e.key==="Enter"&&doLogin()} placeholder="Enter password"
                style={{width:"100%",background:"#0f1117",border:"1px solid #2d3448",borderRadius:8,padding:"10px 14px",paddingRight:44,color:"#f1f5f9",fontSize:14,boxSizing:"border-box",transition:"border .15s,box-shadow .15s"}} />
              <button onClick={()=>setLf(f=>({...f,show:!f.show}))} style={{position:"absolute",right:12,top:"50%",transform:"translateY(-50%)",background:"none",border:"none",color:"#64748b",cursor:"pointer",fontSize:16,padding:2,lineHeight:1}}>{lf.show?"🙈":"👁️"}</button>
            </div>
          </div>
          {lf.err&&<div style={{background:"rgba(239,68,68,0.1)",border:"1px solid rgba(239,68,68,0.3)",borderRadius:8,padding:"10px 14px",color:"#f87171",fontSize:13,marginBottom:16}}>⚠️ {lf.err}</div>}
          <button onClick={doLogin} className="sign-in-btn"
            style={{width:"100%",background:"linear-gradient(135deg,#1d4ed8,#3b82f6)",border:"none",borderRadius:9,padding:"12px",color:"#fff",fontSize:14,fontWeight:700,cursor:"pointer",letterSpacing:"0.02em"}}>
            Sign In →
          </button>
        </div>
        <p style={{textAlign:"center",color:"#334155",fontSize:12,marginTop:14}}>Click a role card above to auto-fill your credentials</p>
      </div>
    </div>
  );

  // ─── DASHBOARD ────────────────────────────────────────────────────────────
  const stepNum = sc?.args.length>0 ? ["2","3"] : ["1","2"];

  return(
    <div style={{fontFamily:"'Segoe UI',system-ui,sans-serif",background:"#0f1117",color:"#e2e8f0",minHeight:"100vh",display:"flex",flexDirection:"column",fontSize:14}}>
      <style>{`
        @keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
        @keyframes slideDown{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
        .anim{animation:fadeUp .3s ease}
        .sc-item:hover{background:#1e2640!important;border-color:#3d4f7a!important}
        .sc-item{transition:all .12s ease}
        .cat-btn:hover{background:#1a1f2e!important}
        .cat-btn{transition:background .12s}
        .log-row:hover{background:rgba(255,255,255,0.025)!important}
        .log-row{transition:background .1s}
        .dismiss:hover{color:#f1f5f9!important}
        .dismiss{transition:color .1s}
        .exec-btn{transition:opacity .15s,transform .1s}
        .exec-btn:hover{opacity:.88}
        .exec-btn:active{transform:scale(.98)}
        input:focus,select:focus{outline:none!important;border-color:#3b82f6!important;box-shadow:0 0 0 3px rgba(59,130,246,0.15)!important}
      `}</style>

      {/* ── Header ── */}
      <div style={{background:"#141824",borderBottom:"1px solid #2d3448",height:52,display:"flex",alignItems:"center",justifyContent:"space-between",padding:"0 16px",flexShrink:0}}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <span style={{fontSize:22}}>🛡️</span>
          <span style={{fontWeight:700,fontSize:16,color:"#f1f5f9",letterSpacing:"-0.3px"}}>Syscall Guardian</span>
          <span style={{color:"#334155",fontSize:12,paddingLeft:10,borderLeft:"1px solid #2d3448",marginLeft:2}}>Secure System Call Interface</span>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div style={{background:"#0f1117",border:"1px solid #2d3448",borderRadius:8,padding:"5px 12px",display:"flex",alignItems:"center",gap:8}}>
            <span style={{fontSize:11,color:"#64748b"}}>Session</span>
            <span style={{...mono,fontSize:13,fontWeight:700,color:sessColor}}>{fmt(sessecs)}</span>
            {sessecs<300&&<span style={{fontSize:10,color:sessColor,animation:"pulse 1.5s infinite"}}>●</span>}
          </div>
          <div style={{background:rm.bg,border:`1px solid ${rm.color}40`,borderRadius:8,padding:"5px 12px",display:"flex",alignItems:"center",gap:6}}>
            <span>{rm.badge}</span>
            <span style={{fontSize:12,fontWeight:600,color:rm.color}}>{user.role}</span>
            <span style={{fontSize:11,color:"#64748b"}}>· {user.username}</span>
          </div>
          <button onClick={doLogout} className="exec-btn" style={{background:"transparent",border:"1px solid #2d3448",borderRadius:8,color:"#94a3b8",padding:"6px 14px",fontSize:13,cursor:"pointer"}}>Sign out</button>
        </div>
      </div>

      {/* ── Alert Banner ── */}
      {activeAlerts.length>0&&(
        <div style={{background:"#130d1a",borderBottom:"1px solid #3b1260",padding:"8px 16px",display:"flex",alignItems:"flex-start",gap:10,flexWrap:"wrap",animation:"slideDown .3s ease"}}>
          <div style={{display:"flex",alignItems:"center",gap:6,paddingTop:2,flexShrink:0}}>
            <span style={{fontSize:15}}>🚨</span>
            <span style={{fontSize:12,fontWeight:700,color:"#d946ef"}}>{activeAlerts.length} Alert{activeAlerts.length>1?"s":""}</span>
          </div>
          <div style={{flex:1,display:"flex",flexWrap:"wrap",gap:6}}>
            {activeAlerts.slice(-4).map(a=>{
              const s={Critical:{bg:"rgba(168,85,247,.12)",bd:"rgba(168,85,247,.4)",c:"#c084fc"},High:{bg:"rgba(239,68,68,.12)",bd:"rgba(239,68,68,.4)",c:"#f87171"},Medium:{bg:"rgba(245,158,11,.12)",bd:"rgba(245,158,11,.4)",c:"#fbbf24"}}[a.sev];
              return(
                <div key={a.id} style={{background:s.bg,border:`1px solid ${s.bd}`,borderRadius:6,padding:"5px 10px",display:"flex",alignItems:"center",gap:8,fontSize:12}}>
                  <span style={{fontWeight:700,color:s.c,fontSize:10}}>{a.sev.toUpperCase()}</span>
                  <span style={{color:"#e2e8f0"}}>{a.title}</span>
                  <span style={{color:"#475569",fontSize:11}}>{a.ts}</span>
                  <button className="dismiss" onClick={()=>setAlerts(p=>p.map(x=>x.id===a.id?{...x,dismissed:true}:x))} style={{background:"none",border:"none",color:"#475569",cursor:"pointer",fontSize:17,lineHeight:1,padding:"0 2px"}}>×</button>
                </div>
              );
            })}
          </div>
          <button className="dismiss" onClick={()=>setAlerts(p=>p.map(a=>({...a,dismissed:true})))} style={{background:"none",border:"none",color:"#475569",fontSize:12,cursor:"pointer",paddingTop:4,flexShrink:0}}>Dismiss all</button>
        </div>
      )}

      {/* ── Tip Banner ── */}
      {tip&&(
        <div style={{background:"rgba(37,99,235,0.07)",borderBottom:"1px solid rgba(37,99,235,0.18)",padding:"8px 16px",display:"flex",alignItems:"center",gap:10,fontSize:13,color:"#93c5fd"}}>
          <span style={{fontSize:16}}>💡</span>
          <span><strong>How to use:</strong> Pick a category on the left → select a syscall → fill in arguments → click Execute. Logged in as <strong style={{color:rm.color}}>{user.role}</strong> — {rm.desc.toLowerCase()}.</span>
          <button onClick={()=>setTip(false)} style={{marginLeft:"auto",background:"none",border:"none",color:"#4b76c8",cursor:"pointer",fontSize:20,lineHeight:1,padding:"0 4px"}}>×</button>
        </div>
      )}

      {/* ── Main layout ── */}
      <div style={{display:"flex",flex:1,overflow:"hidden"}}>

        {/* ── LEFT: Browser ── */}
        <div style={{width:235,background:"#0f1117",borderRight:"1px solid #2d3448",display:"flex",flexDirection:"column",flexShrink:0,overflow:"hidden"}}>
          <div style={{padding:"12px 14px 8px",borderBottom:"1px solid #1e2535"}}>
            <div style={{fontSize:11,fontWeight:700,color:"#64748b",textTransform:"uppercase",letterSpacing:"0.08em"}}>Syscall Browser</div>
            <div style={{fontSize:11,color:"#334155",marginTop:2}}>Pick a category below</div>
          </div>
          {/* Category buttons */}
          <div style={{padding:"6px 8px",borderBottom:"1px solid #1e2535"}}>
            {CATS.map(c=>(
              <button key={c.id} className="cat-btn" onClick={()=>setCat(c.id)} style={{
                width:"100%",background:cat===c.id?"#1a1f2e":"transparent",
                border:`1px solid ${cat===c.id?"#2d3448":"transparent"}`,
                borderRadius:8,padding:"8px 10px",textAlign:"left",cursor:"pointer",
                display:"flex",alignItems:"center",gap:10,marginBottom:2,
              }}>
                <span style={{fontSize:16}}>{c.icon}</span>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontSize:12,fontWeight:600,color:cat===c.id?"#f1f5f9":"#94a3b8"}}>{c.id}</div>
                  <div style={{fontSize:10,color:"#475569",marginTop:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{c.desc}</div>
                </div>
                <span style={{fontSize:10,color:"#334155",flexShrink:0,background:"#141824",borderRadius:4,padding:"1px 6px"}}>{SYSCALL_DB.filter(s=>s.cat===c.id).length}</span>
              </button>
            ))}
          </div>
          {/* Syscall list */}
          <div style={{flex:1,overflowY:"auto",padding:"8px"}}>
            <div style={{fontSize:10,color:"#334155",padding:"2px 6px 8px",fontWeight:600,textTransform:"uppercase",letterSpacing:"0.07em"}}>{cat}</div>
            {SYSCALL_DB.filter(s=>s.cat===cat).map(s=>{
              const ok=canRun(user.role,s.id);
              const sel=sc?.id===s.id;
              return(
                <button key={s.id} className="sc-item" onClick={()=>pickSc(s)} style={{
                  width:"100%",background:sel?"#1a2340":"transparent",
                  border:`1px solid ${sel?"#3d5a9a":"transparent"}`,
                  borderRadius:9,padding:"9px 10px",marginBottom:4,cursor:"pointer",textAlign:"left",
                }}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                    <span style={{fontSize:14,flexShrink:0,opacity:ok?1:.4}}>{s.icon}</span>
                    <span style={{...mono,fontSize:12,fontWeight:700,color:sel?"#bfdbfe":ok?"#94a3b8":"#374151",flex:1,minWidth:0}}>{s.name}</span>
                    <span style={{fontSize:9,fontWeight:700,color:RISK_META[s.risk].color,background:RISK_META[s.risk].bg,border:`1px solid ${RISK_META[s.risk].border}`,borderRadius:4,padding:"1px 5px",flexShrink:0}}>{s.risk}</span>
                  </div>
                  <div style={{fontSize:10,color:ok?"#475569":"#2d3748",lineHeight:1.4,paddingLeft:22}}>{ok?s.desc:"🔒 Not available for your role"}</div>
                </button>
              );
            })}
          </div>
          {/* Role summary */}
          <div style={{padding:"10px 12px",borderTop:"1px solid #1e2535",background:"#141824"}}>
            <div style={{fontSize:10,color:"#475569",marginBottom:4,fontWeight:600,textTransform:"uppercase",letterSpacing:"0.06em"}}>Your access</div>
            <div style={{display:"flex",justifyContent:"space-between",fontSize:11}}>
              <span style={{color:"#64748b"}}>Accessible</span>
              <span style={{fontWeight:700,color:rm.color}}>{user.role==="Admin"?SYSCALL_DB.length:user.role==="Auditor"?0:(ALLOWED[user.role]||[]).length} / {SYSCALL_DB.length}</span>
            </div>
          </div>
        </div>

        {/* ── MIDDLE: Execution ── */}
        <div style={{flex:1,background:"#0f1117",borderRight:"1px solid #2d3448",display:"flex",flexDirection:"column",overflow:"hidden",minWidth:0}}>
          <div style={{padding:"12px 16px 8px",borderBottom:"1px solid #1e2535",flexShrink:0}}>
            <div style={{fontSize:11,fontWeight:700,color:"#64748b",textTransform:"uppercase",letterSpacing:"0.08em"}}>Execution Panel</div>
            <div style={{fontSize:11,color:"#334155",marginTop:2}}>{sc?`Configure and run ${sc.name}`:"Select a syscall from the left to get started"}</div>
          </div>

          <div style={{flex:1,overflowY:"auto",padding:16}}>
            {!sc?(
              <div style={{textAlign:"center",padding:"70px 20px"}}>
                <div style={{fontSize:52,marginBottom:16,opacity:.3}}>⚙️</div>
                <div style={{fontSize:15,fontWeight:600,color:"#475569",marginBottom:10}}>Nothing selected yet</div>
                <div style={{fontSize:13,color:"#334155",lineHeight:1.7,maxWidth:320,margin:"0 auto"}}>
                  Browse the categories on the left, click any syscall to view its details and arguments, then run it here.
                </div>
                <div style={{marginTop:24,display:"flex",alignItems:"center",justifyContent:"center",gap:8,fontSize:12,color:"#475569"}}>
                  <span style={{background:"#1a1f2e",border:"1px solid #2d3448",borderRadius:6,padding:"5px 12px"}}>📁 File I/O → open()</span>
                  <span>is a great place to start</span>
                </div>
              </div>
            ):(
              <div className="anim">
                {/* Syscall info card */}
                <div style={{...card,padding:"16px",marginBottom:14}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:12,marginBottom:12}}>
                    <div style={{display:"flex",alignItems:"center",gap:12}}>
                      <span style={{fontSize:28}}>{sc.icon}</span>
                      <div>
                        <div style={{...mono,fontSize:18,fontWeight:700,color:"#f1f5f9"}}>{sc.name}</div>
                        <div style={{fontSize:12,color:"#64748b",marginTop:2}}>{sc.cat} category</div>
                      </div>
                    </div>
                    <div style={{display:"flex",flexDirection:"column",alignItems:"flex-end",gap:6,flexShrink:0}}>
                      <span style={{fontSize:11,fontWeight:700,color:RISK_META[sc.risk].color,background:RISK_META[sc.risk].bg,border:`1px solid ${RISK_META[sc.risk].border}`,borderRadius:6,padding:"3px 10px"}}>{sc.risk} Risk</span>
                      {canRun(user.role,sc.id)
                        ?<span style={{fontSize:11,color:"#22c55e",background:"rgba(34,197,94,0.1)",border:"1px solid rgba(34,197,94,0.25)",borderRadius:6,padding:"3px 10px"}}>✓ You can run this</span>
                        :<span style={{fontSize:11,color:"#ef4444",background:"rgba(239,68,68,0.1)",border:"1px solid rgba(239,68,68,0.25)",borderRadius:6,padding:"3px 10px"}}>🔒 Restricted for {user.role}</span>
                      }
                    </div>
                  </div>
                  <div style={{fontSize:13,color:"#94a3b8",padding:"10px 14px",background:"#0f1117",borderRadius:8,border:"1px solid #1e2535",lineHeight:1.6}}>{sc.desc}</div>
                </div>

                {/* Arguments */}
                {sc.args.length>0&&(
                  <div style={{...card,padding:"16px",marginBottom:14}}>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:14}}>
                      <span style={{background:"#2563eb",color:"#fff",borderRadius:"50%",width:22,height:22,display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:700,flexShrink:0}}>1</span>
                      <span style={{fontSize:13,fontWeight:600,color:"#e2e8f0"}}>Set the arguments</span>
                    </div>
                    {sc.args.map(arg=>(
                      <div key={arg.n} style={{marginBottom:14}}>
                        <label style={{display:"flex",alignItems:"baseline",gap:8,marginBottom:6}}>
                          <span style={{...mono,fontSize:12,color:"#60a5fa",fontWeight:600}}>{arg.n}</span>
                          <span style={{fontSize:11,color:"#475569"}}>{arg.help}</span>
                        </label>
                        {arg.t==="sel"
                          ?<select value={argv[arg.n]||arg.opts[0]} onChange={e=>setArgv(v=>({...v,[arg.n]:e.target.value}))}
                              style={{width:"100%",background:"#0f1117",border:"1px solid #2d3448",borderRadius:8,padding:"9px 12px",color:"#f1f5f9",fontSize:13,...mono,transition:"border .15s,box-shadow .15s"}}>
                              {arg.opts.map(o=><option key={o} value={o}>{o}</option>)}
                            </select>
                          :<input type={arg.t==="num"?"number":"text"} placeholder={arg.p} value={argv[arg.n]||""} onChange={e=>setArgv(v=>({...v,[arg.n]:e.target.value}))}
                              style={{width:"100%",background:"#0f1117",border:"1px solid #2d3448",borderRadius:8,padding:"9px 12px",color:"#f1f5f9",fontSize:13,...mono,boxSizing:"border-box",transition:"border .15s,box-shadow .15s"}} />
                        }
                      </div>
                    ))}
                  </div>
                )}

                {/* Security checks */}
                <div style={{...card,padding:"16px",marginBottom:14}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:12}}>
                    <span style={{background:"#2563eb",color:"#fff",borderRadius:"50%",width:22,height:22,display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:700,flexShrink:0}}>{sc.args.length>0?"2":"1"}</span>
                    <span style={{fontSize:13,fontWeight:600,color:"#e2e8f0"}}>Security checks</span>
                  </div>
                  <div style={{display:"flex",flexDirection:"column",gap:6}}>
                    {[
                      [true,"Session active",`${fmt(sessecs)} remaining`],
                      [canRun(user.role,sc.id),"Role permission",canRun(user.role,sc.id)?`${user.role} — allowed`:`${user.role} — blocked`],
                      [true,"Input sanitization","Passed"],
                      [true,"Argument validation","Passed"],
                    ].map(([ok,label,detail],i)=>(
                      <div key={i} style={{display:"flex",alignItems:"center",gap:10,padding:"8px 12px",background:ok?"rgba(34,197,94,0.05)":"rgba(239,68,68,0.05)",borderRadius:7,border:`1px solid ${ok?"rgba(34,197,94,0.15)":"rgba(239,68,68,0.15)"}`}}>
                        <span style={{fontSize:15,flexShrink:0}}>{ok?"✅":"❌"}</span>
                        <span style={{fontSize:12,color:"#e2e8f0",flex:1}}>{label}</span>
                        <span style={{...mono,fontSize:11,color:ok?"#22c55e":"#ef4444"}}>{detail}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Execute */}
                <div style={{...card,padding:"16px",marginBottom:14}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:14}}>
                    <span style={{background:"#2563eb",color:"#fff",borderRadius:"50%",width:22,height:22,display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:700,flexShrink:0}}>{sc.args.length>0?"3":"2"}</span>
                    <span style={{fontSize:13,fontWeight:600,color:"#e2e8f0"}}>Execute</span>
                  </div>
                  <button onClick={doExec} disabled={execSt==="running"} className="exec-btn" style={{
                    width:"100%",padding:"13px",borderRadius:10,fontSize:14,fontWeight:700,cursor:execSt==="running"?"wait":"pointer",
                    background:execSt==="running"?"#1e2535":canRun(user.role,sc.id)?"linear-gradient(135deg,#1d4ed8,#3b82f6)":"rgba(239,68,68,0.1)",
                    border:canRun(user.role,sc.id)&&execSt!=="running"?"none":"1px solid rgba(239,68,68,0.3)",
                    color:execSt==="running"?"#64748b":canRun(user.role,sc.id)?"#fff":"#ef4444",
                  }}>
                    {execSt==="running"?"⏳  Running…":canRun(user.role,sc.id)?`▶  Execute  ${sc.name}`:`🔒  Execute  ${sc.name}  (will be blocked)`}
                  </button>
                </div>

                {/* Result */}
                {execRes&&(
                  <div className="anim" style={{...card,padding:"16px",border:`1px solid ${execSt==="success"?"rgba(34,197,94,0.3)":"rgba(239,68,68,0.3)"}`,background:execSt==="success"?"rgba(34,197,94,0.04)":"rgba(239,68,68,0.04)"}}>
                    <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:12}}>
                      <span style={{fontSize:20}}>{execSt==="success"?"✅":"🚫"}</span>
                      <div>
                        <div style={{fontSize:13,fontWeight:700,color:execSt==="success"?"#22c55e":"#ef4444"}}>{execSt==="success"?"Success — syscall executed":"Blocked — permission denied"}</div>
                        <div style={{fontSize:11,color:"#475569",marginTop:1}}>{execSt==="success"?"Logged to audit trail":"Attempt recorded in audit log"}</div>
                      </div>
                    </div>
                    <div style={{background:"#0a0d16",borderRadius:8,padding:"12px 14px",border:"1px solid #1e2535"}}>
                      <pre style={{...mono,margin:0,fontSize:12,color:execSt==="success"?"#86efac":"#fca5a5",whiteSpace:"pre-wrap",lineHeight:1.8}}>{execRes}</pre>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ── RIGHT: Audit Log ── */}
        <div style={{width:310,background:"#0f1117",display:"flex",flexDirection:"column",flexShrink:0,overflow:"hidden"}}>
          <div style={{padding:"12px 14px 8px",borderBottom:"1px solid #1e2535",flexShrink:0}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div style={{fontSize:11,fontWeight:700,color:"#64748b",textTransform:"uppercase",letterSpacing:"0.08em"}}>Audit Log</div>
              <span style={{fontSize:10,color:"#334155",background:"#141824",borderRadius:4,padding:"2px 7px"}}>{fLogs.length} entries</span>
            </div>
            <div style={{fontSize:11,color:"#334155",marginTop:2}}>Every action recorded — click to expand</div>
          </div>

          {/* Filters */}
          <div style={{padding:"8px 10px",borderBottom:"1px solid #1e2535",display:"flex",gap:6,flexShrink:0}}>
            <input placeholder="🔍  Search user or syscall…" value={logF.q} onChange={e=>setLogF(f=>({...f,q:e.target.value}))}
              style={{flex:1,background:"#141824",border:"1px solid #2d3448",borderRadius:7,padding:"7px 10px",color:"#e2e8f0",fontSize:11,minWidth:0,transition:"border .15s,box-shadow .15s"}} />
            <select value={logF.res} onChange={e=>setLogF(f=>({...f,res:e.target.value}))}
              style={{background:"#141824",border:"1px solid #2d3448",borderRadius:7,padding:"7px 8px",color:"#94a3b8",fontSize:11,cursor:"pointer"}}>
              <option value="all">All</option>
              <option value="success">✓ Success</option>
              <option value="blocked">⊘ Blocked</option>
            </select>
          </div>

          {/* Log entries */}
          <div style={{flex:1,overflowY:"auto"}}>
            {fLogs.length===0&&(
              <div style={{textAlign:"center",padding:"40px 16px",color:"#334155",fontSize:12}}>
                <div style={{fontSize:28,marginBottom:8,opacity:.4}}>📋</div>
                No entries match your filter
              </div>
            )}
            {fLogs.map(l=>(
              <div key={l.id} className="log-row" onClick={()=>setExpanded(expanded===l.id?null:l.id)}
                style={{padding:"10px 12px",borderBottom:"1px solid #141824",cursor:"pointer",
                  borderLeft:`3px solid ${l.result==="success"?"rgba(34,197,94,0.5)":"rgba(239,68,68,0.5)"}`,
                  background:expanded===l.id?"rgba(37,99,235,0.05)":"transparent"}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:5}}>
                  <span style={{...mono,fontSize:12,fontWeight:700,color:"#60a5fa"}}>{l.syscall}</span>
                  <span style={{fontSize:10,fontWeight:700,color:l.result==="success"?"#22c55e":"#ef4444",background:l.result==="success"?"rgba(34,197,94,0.1)":"rgba(239,68,68,0.1)",padding:"2px 8px",borderRadius:4}}>
                    {l.result==="success"?"✓ OK":"⊘ Blocked"}
                  </span>
                </div>
                <div style={{display:"flex",gap:6,fontSize:11,color:"#475569",flexWrap:"wrap"}}>
                  <span style={{color:ROLE_META[l.role]?.color||"#94a3b8",fontWeight:600}}>{l.user}</span>
                  <span style={{color:"#2d3748"}}>·</span>
                  <span>{l.ts}</span>
                  <span style={{color:"#2d3748"}}>·</span>
                  <span>{l.ip}</span>
                </div>

                {expanded===l.id&&(
                  <div className="anim" style={{marginTop:8,padding:"10px 12px",background:"#0a0d16",borderRadius:8,border:"1px solid #1e2535"}}>
                    <div style={{fontSize:10,color:"#475569",fontWeight:700,textTransform:"uppercase",letterSpacing:"0.07em",marginBottom:8}}>Arguments passed</div>
                    {Object.entries(l.args).length>0
                      ?Object.entries(l.args).map(([k,v])=>(
                          <div key={k} style={{display:"flex",gap:6,fontSize:11,marginBottom:5}}>
                            <span style={{...mono,color:"#60a5fa",minWidth:80,flexShrink:0}}>{k}</span>
                            <span style={{color:"#334155"}}>=</span>
                            <span style={{...mono,color:"#94a3b8",wordBreak:"break-all"}}>{String(v)}</span>
                          </div>
                        ))
                      :<div style={{fontSize:11,color:"#334155"}}>No arguments</div>
                    }
                    <div style={{marginTop:8,paddingTop:8,borderTop:"1px solid #1e2535",display:"flex",gap:12,fontSize:10,color:"#334155"}}>
                      <span>Log #{l.id}</span>
                      <span>·</span>
                      <span>Role: <span style={{color:ROLE_META[l.role]?.color}}>{l.role}</span></span>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Stats */}
          <div style={{padding:"10px 12px",borderTop:"1px solid #1e2535",display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,flexShrink:0}}>
            {[
              ["Total calls",  logs.length,                                "#e2e8f0"],
              ["Successful",   logs.filter(l=>l.result==="success").length, "#22c55e"],
              ["Blocked",      logs.filter(l=>l.result==="blocked").length, "#ef4444"],
              ["Alerts fired", alerts.length,                               "#f59e0b"],
            ].map(([label,val,c])=>(
              <div key={label} style={{background:"#141824",borderRadius:7,padding:"8px 10px"}}>
                <div style={{fontSize:10,color:"#475569",marginBottom:3}}>{label}</div>
                <div style={{fontSize:18,fontWeight:700,color:c}}>{val}</div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}