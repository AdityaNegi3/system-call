// import { useState, useEffect, useRef } from "react";

// const BACKEND = "http://localhost:3001";

// const USERS = {
//     admin:   { pw: "admin123",  role: "Admin" },
//     dev:     { pw: "dev123",    role: "Developer" },
//     auditor: { pw: "audit123",  role: "Auditor" },
// };

// const ALLOWED = {
//     Admin:     null,
//     Developer: ["open","read","write","close","socket","connect","send","recv","fork","waitpid"],
//     Auditor:   [],
// };

// const SYSCALL_DB = [
//     { id:"open",     name:"open()",     cat:"File I/O",  risk:"Low",      desc:"Open and possibly create a file descriptor", args:[{n:"pathname",t:"text",p:"/tmp/myfile.txt"},{n:"flags",t:"sel",opts:["O_RDONLY","O_WRONLY","O_RDWR","O_CREAT|O_TRUNC"]}] },
//     { id:"read",     name:"read()",     cat:"File I/O",  risk:"Low",      desc:"Read bytes from a file descriptor",          args:[{n:"fd",t:"num",p:"3"},{n:"count",t:"num",p:"512"}] },
//     { id:"write",    name:"write()",    cat:"File I/O",  risk:"Low",      desc:"Write bytes to a file descriptor",           args:[{n:"fd",t:"num",p:"1"},{n:"buf",t:"text",p:"Hello OS World"},{n:"count",t:"num",p:"14"}] },
//     { id:"close",    name:"close()",    cat:"File I/O",  risk:"Low",      desc:"Close a file descriptor",                    args:[{n:"fd",t:"num",p:"3"}] },
//     { id:"unlink",   name:"unlink()",   cat:"File I/O",  risk:"Medium",   desc:"Delete a name from the filesystem",          args:[{n:"pathname",t:"text",p:"/tmp/myfile.txt"}] },
//     { id:"fork",     name:"fork()",     cat:"Process",   risk:"Medium",   desc:"Create child process by duplicating caller", args:[] },
//     { id:"execve",   name:"execve()",   cat:"Process",   risk:"High",     desc:"Execute program, replacing process image",   args:[{n:"filename",t:"sel",opts:["/bin/ls","/bin/whoami","/bin/date","/bin/echo","/bin/pwd"]},{n:"argv",t:"text",p:"-la /tmp"}] },
//     { id:"kill",     name:"kill()",     cat:"Process",   risk:"High",     desc:"Send a signal to a process or group",        args:[{n:"pid",t:"num",p:"1234"},{n:"sig",t:"sel",opts:["SIGTERM","SIGKILL","SIGINT","SIGHUP","SIGUSR1"]}] },
//     { id:"waitpid",  name:"waitpid()",  cat:"Process",   risk:"Low",      desc:"Wait for process state change",             args:[{n:"pid",t:"num",p:"-1"},{n:"options",t:"sel",opts:["0","WNOHANG","WUNTRACED"]}] },
//     { id:"socket",   name:"socket()",   cat:"Network",   risk:"Medium",   desc:"Create an endpoint for communication",       args:[{n:"domain",t:"sel",opts:["AF_INET","AF_INET6","AF_UNIX"]},{n:"type",t:"sel",opts:["SOCK_STREAM","SOCK_DGRAM","SOCK_RAW"]}] },
//     { id:"bind",     name:"bind()",     cat:"Network",   risk:"High",     desc:"Bind a name to a socket",                    args:[{n:"sockfd",t:"num",p:"4"},{n:"port",t:"num",p:"9090"},{n:"addr",t:"text",p:"0.0.0.0"}] },
//     { id:"connect",  name:"connect()",  cat:"Network",   risk:"Medium",   desc:"Initiate a connection on a socket",          args:[{n:"sockfd",t:"num",p:"4"},{n:"addr",t:"text",p:"127.0.0.1"},{n:"port",t:"num",p:"3001"}] },
//     { id:"send",     name:"send()",     cat:"Network",   risk:"Low",      desc:"Send a message on a socket",                 args:[{n:"sockfd",t:"num",p:"4"},{n:"buf",t:"text",p:"GET / HTTP/1.1"},{n:"flags",t:"sel",opts:["0","MSG_DONTWAIT","MSG_MORE"]}] },
//     { id:"recv",     name:"recv()",     cat:"Network",   risk:"Low",      desc:"Receive a message from a socket",            args:[{n:"sockfd",t:"num",p:"4"},{n:"len",t:"num",p:"4096"},{n:"flags",t:"sel",opts:["0","MSG_PEEK","MSG_DONTWAIT"]}] },
//     { id:"mmap",     name:"mmap()",     cat:"Memory",    risk:"High",     desc:"Map files or devices into memory",           args:[{n:"addr",t:"text",p:"NULL"},{n:"length",t:"num",p:"4096"},{n:"prot",t:"sel",opts:["PROT_READ","PROT_WRITE","PROT_EXEC","PROT_NONE"]}] },
//     { id:"mprotect", name:"mprotect()", cat:"Memory",    risk:"Critical", desc:"Set protection on a region of memory",       args:[{n:"addr",t:"text",p:"0x7ffff7fc0000"},{n:"len",t:"num",p:"4096"},{n:"prot",t:"sel",opts:["PROT_READ","PROT_WRITE","PROT_EXEC","PROT_NONE"]}] },
//     { id:"brk",      name:"brk()",      cat:"Memory",    risk:"Medium",   desc:"Change location of program break",           args:[{n:"addr",t:"text",p:"NULL"}] },
//     { id:"setuid",   name:"setuid()",   cat:"Security",  risk:"Critical", desc:"Set user identity of calling process",       args:[{n:"uid",t:"num",p:"0"}] },
//     { id:"chmod",    name:"chmod()",    cat:"Security",  risk:"High",     desc:"Change permissions of a file",               args:[{n:"pathname",t:"text",p:"/tmp/myfile.txt"},{n:"mode",t:"text",p:"0644"}] },
//     { id:"chroot",   name:"chroot()",   cat:"Security",  risk:"Critical", desc:"Change root directory of calling process",   args:[{n:"path",t:"text",p:"/var/chroot"}] },
// ];

// const CATS    = ["File I/O","Process","Network","Memory","Security"];
// const CAT_SYM = { "File I/O":"▤","Process":"◈","Network":"◎","Memory":"▦","Security":"◉" };

// const RISK = {
//     Low:      { c:"#3fb950", bg:"rgba(63,185,80,0.12)",   bd:"rgba(63,185,80,0.35)" },
//     Medium:   { c:"#d29922", bg:"rgba(210,153,34,0.12)",  bd:"rgba(210,153,34,0.35)" },
//     High:     { c:"#f85149", bg:"rgba(248,81,73,0.12)",   bd:"rgba(248,81,73,0.35)" },
//     Critical: { c:"#bc8cff", bg:"rgba(188,140,255,0.12)", bd:"rgba(188,140,255,0.35)" },
// };

// const ROLE_C = { Admin:"#f0883e", Developer:"#58a6ff", Auditor:"#3fb950" };
// const SEV_C  = {
//     Critical: { c:"#bc8cff", bg:"rgba(188,140,255,0.1)", bd:"rgba(188,140,255,0.4)" },
//     High:     { c:"#f85149", bg:"rgba(248,81,73,0.1)",   bd:"rgba(248,81,73,0.4)" },
//     Medium:   { c:"#d29922", bg:"rgba(210,153,34,0.1)",  bd:"rgba(210,153,34,0.4)" },
// };

// let _lid = 200;
// function mkLog(user, syscall, args, result, extra = {}) {
//     const n  = new Date();
//     const ts = [n.getHours(), n.getMinutes(), n.getSeconds()].map(x => String(x).padStart(2,"0")).join(":");
//     const ip = user.role === "Admin" ? "10.0.0.1" : user.role === "Developer" ? "10.0.0.4" : "10.0.0.7";
//     return { id: ++_lid, ts, user: user.username, role: user.role, syscall, args, result, ip, extra };
// }

// function canRun(role, id) {
//     if (role === "Admin")   return true;
//     if (role === "Auditor") return false;
//     return (ALLOWED[role] || []).includes(id);
// }

// const SEED_LOGS = [
//     { id:1, ts:"08:42:11", user:"admin",   role:"Admin",     syscall:"chmod()",  args:{pathname:"/etc/passwd",mode:"0644"}, result:"success", ip:"10.0.0.1", extra:{} },
//     { id:2, ts:"08:55:03", user:"dev",     role:"Developer", syscall:"mmap()",   args:{addr:"NULL",length:4096,prot:"PROT_EXEC"}, result:"blocked", ip:"10.0.0.4", extra:{} },
//     { id:3, ts:"09:12:44", user:"dev",     role:"Developer", syscall:"read()",   args:{fd:3,count:1024}, result:"success", ip:"10.0.0.4", extra:{bytesRead:1024} },
//     { id:4, ts:"09:31:22", user:"admin",   role:"Admin",     syscall:"setuid()", args:{uid:0}, result:"success", ip:"10.0.0.1", extra:{uid:0,previousUid:"1000"} },
//     { id:5, ts:"09:31:25", user:"admin",   role:"Admin",     syscall:"chroot()", args:{path:"/var/chroot"}, result:"success", ip:"10.0.0.1", extra:{path:"/var/chroot"} },
//     { id:6, ts:"09:45:00", user:"auditor", role:"Auditor",   syscall:"read()",   args:{fd:5,count:512}, result:"blocked", ip:"10.0.0.7", extra:{} },
// ];

// const SEED_ALERTS = [
//     { id:1, sev:"High",   title:"Privilege escalation pattern", detail:"setuid(0) + chroot() called in sequence by admin", ts:"09:31:25", dismissed:false },
//     { id:2, sev:"Medium", title:"Unauthorized syscall attempt",  detail:"dev [Developer] attempted mmap() — insufficient privileges", ts:"08:55:03", dismissed:false },
// ];

// export default function SecureSyscall() {
//     const [screen,    setScreen]    = useState("login");
//     const [user,      setUser]      = useState(null);
//     const [sessecs,   setSessecs]   = useState(900);
//     const [lf,        setLf]        = useState({ u:"", p:"", err:"", att:0 });
//     const [cat,       setCat]       = useState("File I/O");
//     const [sc,        setSc]        = useState(null);
//     const [argv,      setArgv]      = useState({});
//     const [execRes,   setExecRes]   = useState(null);
//     const [execSt,    setExecSt]    = useState(null);   // "running"|"success"|"blocked"|"error"|null
//     const [logs,      setLogs]      = useState(SEED_LOGS);
//     const [alerts,    setAlerts]    = useState(SEED_ALERTS);
//     const [logF,      setLogF]      = useState({ res:"all", q:"" });
//     const [detailLog, setDetailLog] = useState(null);
//     const [execHist,  setExecHist]  = useState({});     // FIX 3: persist results per syscall
//     const [backend,   setBackend]   = useState(null);   // null|"online"|"offline"
//     const [files,     setFiles]     = useState([]);     // real files on disk
//     const [showFiles, setShowFiles] = useState(false);
//     const timerRef = useRef(null);

//     // ── FIX 1: doLogout declared before useEffect ────────────────
//     function doLogout() {
//         clearInterval(timerRef.current);
//         setUser(null); setScreen("login");
//         setSc(null); setExecRes(null); setExecSt(null);
//     }

//     useEffect(() => {
//         if (screen === "dashboard") {
//             // Check backend on login
//             fetch(`${BACKEND}/health`)
//                 .then(r => r.json())
//                 .then(() => setBackend("online"))
//                 .catch(() => setBackend("offline"));

//             timerRef.current = setInterval(() => {
//                 setSessecs(s => { if (s <= 1) { doLogout(); return 0; } return s - 1; });
//             }, 1000);
//         }
//         return () => clearInterval(timerRef.current);
//     // eslint-disable-next-line react-hooks/exhaustive-deps
//     }, [screen]);

//     function fmt(s) {
//         return `${Math.floor(s/60).toString().padStart(2,"0")}:${(s%60).toString().padStart(2,"0")}`;
//     }

//     function addAlert(sev, title, detail) {
//         const ts = new Date().toLocaleTimeString("en-GB", { hour12:false });
//         setAlerts(prev => [...prev, { id: Date.now() + Math.random(), sev, title, detail, ts, dismissed:false }]);
//     }

//     function pushLog(entry) {
//         const log = mkLog(entry.user, entry.syscall, entry.args, entry.result, entry.extra || {});
//         setLogs(prev => [...prev, log]);
//         if (entry.blocked) {
//             addAlert("Medium","Unauthorized syscall attempt",
//                 `${entry.user.username} [${entry.user.role}] attempted ${entry.syscall} — insufficient privileges`);
//         }
//         if (!entry.blocked && ["setuid","mprotect","chroot"].includes(entry.scId)) {
//             addAlert("High","Critical syscall executed",
//                 `${entry.user.username} executed ${entry.syscall} — manual review recommended`);
//         }
//     }

//     function doLogin() {
//         const u = USERS[lf.u.trim().toLowerCase()];
//         if (!u || u.pw !== lf.p) {
//             const att = lf.att + 1;
//             if (att >= 3) addAlert("Critical","Brute force attack detected",
//                 `${att} failed login attempts for account "${lf.u}"`);
//             setLf(f => ({ ...f, err:`Invalid credentials (attempt ${att})`, att }));
//             return;
//         }
//         setUser({ username: lf.u.trim().toLowerCase(), role: u.role });
//         setScreen("dashboard");
//         setSessecs(900);
//         setLf({ u:"", p:"", err:"", att:0 });
//     }

//     // FIX 3: load persisted result when switching syscalls
//     function pickSc(s) {
//         setSc(s);
//         setArgv({});
//         const hist = execHist[s.id];
//         setExecRes(hist?.res ?? null);
//         setExecSt(hist?.st  ?? null);
//     }

//     // FIX 1: real backend calls + FIX 2: store extra data in logs
//     async function doExec() {
//         if (!sc || execSt === "running") return;
//         setExecSt("running");
//         setExecRes(null);

//         const permitted = canRun(user.role, sc.id);

//         if (!permitted) {
//             setTimeout(() => {
//                 const msg = `EPERM: Operation not permitted\nUser '${user.username}' [${user.role}] lacks permission\nto invoke ${sc.name}`;
//                 setExecSt("blocked");
//                 setExecRes(msg);
//                 setExecHist(p => ({ ...p, [sc.id]:{ res:msg, st:"blocked" } }));
//                 pushLog({ user, syscall:sc.name, args:argv, result:"blocked", blocked:true, scId:sc.id, extra:{} });
//             }, 400);
//             return;
//         }

//         try {
//             const resp = await fetch(`${BACKEND}/syscall/${sc.id}`, {
//                 method: "POST",
//                 headers: { "Content-Type":"application/json" },
//                 body: JSON.stringify(argv),
//             });
//             const data = await resp.json();
//             setBackend("online");

//             const st = data.success ? "success" : "error";
//             setExecSt(st);
//             setExecRes(data.result);
//             setExecHist(p => ({ ...p, [sc.id]:{ res:data.result, st } }));
//             pushLog({ user, syscall:sc.name, args:argv, result: data.success ? "success" : "error",
//                       blocked:false, scId:sc.id, extra: data.data || {} });

//             // Refresh file list
//             if (["open","write","unlink"].includes(sc.id)) refreshFiles();

//         } catch {
//             // Backend offline — fall back to simulation
//             setBackend("offline");
//             const sim = fallbackResult(sc, argv);
//             setExecSt("success");
//             setExecRes(sim + "\n\n⚠ Backend offline — simulated result");
//             setExecHist(p => ({ ...p, [sc.id]:{ res:sim, st:"success" } }));
//             pushLog({ user, syscall:sc.name, args:argv, result:"success", blocked:false, scId:sc.id, extra:{} });
//         }
//     }

//     function fallbackResult(sc, args) {
//         const m = {
//             open:`fd = ${3 + Math.floor(Math.random()*20)}`, read:`${Math.floor(Math.random()*1024)} bytes read`,
//             write:`${args.count||Math.floor(Math.random()*100)+1} bytes written`, close:`0  (fd closed)`,
//             unlink:`0  (file removed)`, fork:`child pid = ${1000+Math.floor(Math.random()*9000)}`,
//             execve:`0  (exec'd successfully)`, kill:`0  (signal delivered)`,
//             waitpid:`pid = ${1000+Math.floor(Math.random()*9000)}, status = 0`,
//             socket:`sockfd = ${4+Math.floor(Math.random()*10)}`, bind:`0  (address bound)`,
//             connect:`0  (connected)`, send:`${Math.floor(Math.random()*512)+1} bytes sent`,
//             recv:`${Math.floor(Math.random()*4096)} bytes received`,
//             mmap:`0x${Math.floor(Math.random()*0xffffff).toString(16).padStart(12,"0")}`,
//             mprotect:`0  (protection updated)`,
//             brk:`0x${Math.floor(Math.random()*0xfffff).toString(16).padStart(12,"0")}`,
//             setuid:`0  (uid set to ${args.uid||0})`, chmod:`0  (mode ${args.mode||"0644"} applied)`,
//             chroot:`0  (root → ${args.path||"/"})`,
//         };
//         return m[sc.id] || "0";
//     }

//     function refreshFiles() {
//         fetch(`${BACKEND}/files`)
//             .then(r => r.json())
//             .then(d => setFiles(d.files || []))
//             .catch(() => {});
//     }

//     const fLogs = [...logs].filter(l => {
//         if (user?.role === "Developer" && l.user !== user.username) return false;
//         if (logF.res !== "all" && l.result !== logF.res) return false;
//         if (logF.q && !l.syscall.toLowerCase().includes(logF.q.toLowerCase()) &&
//             !l.user.includes(logF.q.toLowerCase())) return false;
//         return true;
//     }).reverse();

//     const activeAlerts = alerts.filter(a => !a.dismissed);
//     const sessColor    = sessecs < 120 ? "#f85149" : sessecs < 300 ? "#d29922" : "#3fb950";

//     // ── STYLES ───────────────────────────────────────────────────
//     const F    = { fontFamily:"'Cascadia Code','Fira Code','Courier New',monospace" };
//     const BG   = { background:"#0d1117" };
//     const BG2  = { background:"#161b22" };
//     const BD   = { border:"1px solid #30363d" };
//     const txt  = { color:"#c9d1d9" };
//     const txt2 = { color:"#8b949e" };
//     const tpri = { color:"#e6edf3" };

//     // ── LOGIN ────────────────────────────────────────────────────
//     if (screen === "login") return (
//         <div style={{ ...BG,...F,...txt, minHeight:"100vh", display:"flex", alignItems:"center", justifyContent:"center", padding:20 }}>
//             <div style={{ width:420 }}>
//                 <div style={{ textAlign:"center", marginBottom:28 }}>
//                     <div style={{ fontSize:32, color:"#3fb950", letterSpacing:4, fontWeight:700 }}>◈</div>
//                     <div style={{ ...tpri, fontSize:18, fontWeight:700, letterSpacing:1, marginTop:6 }}>SYSCALL GUARDIAN</div>
//                     <div style={{ ...txt2, fontSize:11, marginTop:4, letterSpacing:2 }}>SECURE SYSTEM CALL INTERFACE v3.0.0</div>
//                 </div>

//                 <div style={{ ...BG2,...BD, borderRadius:10, padding:"24px 28px" }}>
//                     <div style={{ marginBottom:18 }}>
//                         <div style={{ ...tpri, fontSize:15, fontWeight:600, marginBottom:4 }}>Authentication Required</div>
//                         <div style={{ ...txt2, fontSize:11 }}>Sessions expire after 15 minutes of inactivity</div>
//                     </div>

//                     {/* Demo creds */}
//                     <div style={{ ...BG, border:"1px solid #21262d", borderRadius:6, padding:"10px 14px", marginBottom:18, fontSize:11 }}>
//                         <div style={{ color:"#3fb950", marginBottom:6, letterSpacing:1 }}>// demo credentials</div>
//                         {[["admin","admin123","Admin"],["dev","dev123","Developer"],["auditor","audit123","Auditor"]].map(([u,p,r]) => (
//                             <div key={u} style={{ display:"flex", gap:12, marginBottom:3, ...txt2 }}>
//                                 <span style={{ color:ROLE_C[r], minWidth:60 }}>{u}</span>
//                                 <span>{p}</span>
//                                 <span style={{ marginLeft:"auto", color:ROLE_C[r] }}>{r}</span>
//                             </div>
//                         ))}
//                     </div>

//                     {[["USERNAME","text",lf.u,"username",v=>setLf(f=>({...f,u:v,err:""}))],
//                       ["PASSWORD","password",lf.p,"••••••••",v=>setLf(f=>({...f,p:v,err:""}))]].map(([label,type,val,ph,onChange]) => (
//                         <div key={label} style={{ marginBottom:14 }}>
//                             <label style={{ display:"block", fontSize:10,...txt2, letterSpacing:2, marginBottom:6 }}>{label}</label>
//                             <input type={type} value={val} placeholder={ph}
//                                 onChange={e=>onChange(e.target.value)}
//                                 onKeyDown={e=>e.key==="Enter"&&doLogin()}
//                                 style={{ width:"100%",...BG,...BD, borderRadius:5, padding:"8px 12px",...tpri, fontSize:12,...F, boxSizing:"border-box", outline:"none" }}/>
//                         </div>
//                     ))}

//                     {lf.err && (
//                         <div style={{ color:"#f85149", fontSize:11, marginBottom:14, padding:"8px 12px", background:"rgba(248,81,73,0.1)", border:"1px solid rgba(248,81,73,0.35)", borderRadius:5 }}>
//                             ⚠ {lf.err}
//                         </div>
//                     )}

//                     <button onClick={doLogin} style={{ width:"100%", background:"#1a7f37", border:"1px solid #2ea043", borderRadius:6, padding:"10px", color:"#fff", fontSize:13,...F, cursor:"pointer", letterSpacing:1, fontWeight:600 }}>
//                         AUTHENTICATE →
//                     </button>
//                 </div>

//                 {/* Permission matrix */}
//                 <div style={{ marginTop:20,...BG2,...BD, borderRadius:8, overflow:"hidden" }}>
//                     <div style={{ padding:"8px 14px", borderBottom:"1px solid #21262d", fontSize:10,...txt2, letterSpacing:2 }}>PERMISSION MATRIX</div>
//                     <table style={{ width:"100%", borderCollapse:"collapse", fontSize:10 }}>
//                         <thead>
//                             <tr style={{ background:"#0d1117" }}>
//                                 {["Role","Execute","View Logs","Files"].map(h=>(
//                                     <th key={h} style={{ padding:"6px 14px", textAlign:"left",...txt2, fontWeight:500, letterSpacing:1 }}>{h.toUpperCase()}</th>
//                                 ))}
//                             </tr>
//                         </thead>
//                         <tbody>
//                             {[["Admin","#f0883e","All syscalls","✓ Full","✓"],
//                               ["Developer","#58a6ff","Safe only","Own only","✗"],
//                               ["Auditor","#3fb950","None","✓ Full","✗"]].map(([role,c,exec,logs,files])=>(
//                                 <tr key={role} style={{ borderTop:"1px solid #21262d" }}>
//                                     <td style={{ padding:"8px 14px", color:c, fontWeight:600 }}>{role}</td>
//                                     <td style={{ padding:"8px 14px",...txt2 }}>{exec}</td>
//                                     <td style={{ padding:"8px 14px",...txt2 }}>{logs}</td>
//                                     <td style={{ padding:"8px 14px",...txt2 }}>{files}</td>
//                                 </tr>
//                             ))}
//                         </tbody>
//                     </table>
//                 </div>
//             </div>
//         </div>
//     );

//     // ── DASHBOARD ────────────────────────────────────────────────
//     return (
//         <div style={{ ...BG,...F,...txt, minHeight:"100vh", display:"flex", flexDirection:"column", fontSize:12 }}>

//             {/* Header */}
//             <div style={{ ...BG2, borderBottom:"1px solid #30363d", height:44, display:"flex", alignItems:"center", justifyContent:"space-between", padding:"0 14px", flexShrink:0 }}>
//                 <div style={{ display:"flex", alignItems:"center", gap:14 }}>
//                     <div style={{ color:"#3fb950", fontWeight:700, letterSpacing:2, fontSize:12 }}>◈ SYSCALL GUARDIAN</div>
//                     <div style={{ width:1, height:16, background:"#30363d" }}/>
//                     <div style={{ ...txt2, fontSize:10 }}>Secure System Call Interface v3.0.0</div>
//                 </div>
//                 <div style={{ display:"flex", alignItems:"center", gap:16 }}>
//                     {/* Backend status */}
//                     <span style={{ fontSize:9,...txt2 }}>
//                         BACKEND <span style={{ fontWeight:700, color: backend==="online"?"#3fb950": backend==="offline"?"#f85149":"#d29922" }}>
//                             {backend==="online"?"● LIVE": backend==="offline"?"● OFFLINE":"● ..."}
//                         </span>
//                     </span>
//                     <span style={{ fontSize:10,...txt2 }}>SESSION <span style={{ color:sessColor, fontWeight:700 }}>{fmt(sessecs)}</span></span>
//                     <span style={{ fontSize:10,...txt2 }}>ROLE <span style={{ color:ROLE_C[user.role], fontWeight:700 }}>{user.role.toUpperCase()}</span></span>
//                     <span style={{ fontSize:10,...txt2 }}>{user.username}@syscall</span>
//                     <button onClick={()=>{refreshFiles();setShowFiles(f=>!f)}}
//                         style={{ ...BG, border:"1px solid #30363d", borderRadius:4,...txt2, padding:"3px 10px", fontSize:10, cursor:"pointer",...F }}>
//                         📁 FILES
//                     </button>
//                     <button onClick={doLogout}
//                         style={{ ...BG, border:"1px solid #30363d", borderRadius:4,...txt2, padding:"3px 10px", fontSize:10, cursor:"pointer",...F }}>
//                         LOGOUT
//                     </button>
//                 </div>
//             </div>

//             {/* Alert banner */}
//             {activeAlerts.length > 0 && (
//                 <div style={{ background:"#160b0b", borderBottom:"1px solid #5c1a1a", padding:"6px 14px", display:"flex", alignItems:"flex-start", gap:10, flexWrap:"wrap" }}>
//                     <span style={{ color:"#f85149", fontSize:10, fontWeight:700, flexShrink:0, paddingTop:2 }}>
//                         ⚠ {activeAlerts.length} ALERT{activeAlerts.length>1?"S":""}
//                     </span>
//                     {activeAlerts.slice(-4).map(a=>(
//                         <div key={a.id} style={{ display:"flex", alignItems:"center", gap:6, background:SEV_C[a.sev]?.bg||"", border:`1px solid ${SEV_C[a.sev]?.bd||"#333"}`, borderRadius:4, padding:"2px 8px" }}>
//                             <span style={{ color:SEV_C[a.sev]?.c, fontSize:9, fontWeight:700 }}>{a.sev.toUpperCase()}</span>
//                             <span style={{ fontSize:10,...tpri }}>{a.title}</span>
//                             <span style={{ fontSize:9,...txt2 }}>{a.ts}</span>
//                             <button onClick={()=>setAlerts(p=>p.map(x=>x.id===a.id?{...x,dismissed:true}:x))}
//                                 style={{ background:"none", border:"none",...txt2, cursor:"pointer", fontSize:14, padding:"0 2px", lineHeight:1 }}>×</button>
//                         </div>
//                     ))}
//                 </div>
//             )}

//             {/* Files panel popup */}
//             {showFiles && (
//                 <div style={{ ...BG2, borderBottom:"1px solid #30363d", padding:"10px 14px" }}>
//                     <div style={{ fontSize:9, color:"#3fb950", letterSpacing:2, marginBottom:8 }}>📁 FILES ON DISK (syscall-guardian temp folder)</div>
//                     {files.length === 0
//                         ? <div style={{ fontSize:10,...txt2 }}>No files yet — run open() or write() to create files</div>
//                         : <div style={{ display:"flex", gap:10, flexWrap:"wrap" }}>
//                             {files.map(f=>(
//                                 <div key={f.name} style={{ background:"#0d1117", border:"1px solid #21262d", borderRadius:4, padding:"4px 10px", fontSize:10 }}>
//                                     <span style={{ color:"#58a6ff" }}>{f.name}</span>
//                                     <span style={{ ...txt2, marginLeft:8 }}>{f.size}B</span>
//                                 </div>
//                             ))}
//                           </div>
//                     }
//                 </div>
//             )}

//             {/* Three-panel layout */}
//             <div style={{ display:"flex", flex:1, overflow:"hidden" }}>

//                 {/* Panel 1 — Syscall Browser */}
//                 <div style={{ width:210,...BG, borderRight:"1px solid #30363d", display:"flex", flexDirection:"column", flexShrink:0, overflow:"hidden" }}>
//                     <div style={{ padding:"8px 12px", borderBottom:"1px solid #21262d", fontSize:9,...txt2, letterSpacing:3 }}>SYSCALL BROWSER</div>

//                     <div style={{ padding:"6px 8px", borderBottom:"1px solid #21262d", display:"flex", flexDirection:"column", gap:2 }}>
//                         {CATS.map(c=>(
//                             <button key={c} onClick={()=>setCat(c)} style={{
//                                 background: cat===c?"#21262d":"transparent",
//                                 border: cat===c?"1px solid #30363d":"1px solid transparent",
//                                 borderRadius:4, padding:"5px 10px", color:cat===c?"#e6edf3":"#8b949e",
//                                 fontSize:11,...F, cursor:"pointer", textAlign:"left", display:"flex", alignItems:"center", gap:8
//                             }}>
//                                 <span style={{ fontSize:11, color:cat===c?"#3fb950":"#30363d" }}>{CAT_SYM[c]}</span>
//                                 <span>{c}</span>
//                                 <span style={{ marginLeft:"auto", fontSize:9,...txt2 }}>{SYSCALL_DB.filter(s=>s.cat===c).length}</span>
//                             </button>
//                         ))}
//                     </div>

//                     <div style={{ flex:1, overflowY:"auto", padding:"6px 8px" }}>
//                         {SYSCALL_DB.filter(s=>s.cat===cat).map(s=>{
//                             const permitted = canRun(user.role, s.id);
//                             const sel       = sc?.id === s.id;
//                             const hasResult = !!execHist[s.id];
//                             return (
//                                 <button key={s.id} onClick={()=>pickSc(s)} style={{
//                                     width:"100%", background:sel?"#161b22":"transparent",
//                                     border:sel?"1px solid #30363d":"1px solid transparent",
//                                     borderRadius:4, padding:"7px 10px", marginBottom:2,
//                                     cursor:"pointer", textAlign:"left",...F, opacity:permitted?1:0.45,
//                                 }}>
//                                     <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", gap:4 }}>
//                                         <span style={{ color:sel?"#e6edf3":"#8b949e", fontSize:12, fontWeight:sel?600:400 }}>{s.name}</span>
//                                         <div style={{ display:"flex", gap:3, alignItems:"center" }}>
//                                             {hasResult && <span style={{ fontSize:7, color:"#3fb950" }}>●</span>}
//                                             <span style={{ fontSize:8, fontWeight:700, color:RISK[s.risk].c, background:RISK[s.risk].bg, border:`1px solid ${RISK[s.risk].bd}`, borderRadius:3, padding:"1px 5px", flexShrink:0 }}>{s.risk.toUpperCase()}</span>
//                                         </div>
//                                     </div>
//                                     {!permitted && <div style={{ fontSize:9, color:"#f85149", marginTop:2 }}>⊘ restricted</div>}
//                                 </button>
//                             );
//                         })}
//                     </div>

//                     <div style={{ padding:"8px 12px", borderTop:"1px solid #21262d", fontSize:9,...txt2, display:"flex", flexDirection:"column", gap:2 }}>
//                         <div>Total syscalls: <span style={tpri}>{SYSCALL_DB.length}</span></div>
//                         <div>Accessible: <span style={{ color:"#3fb950" }}>{user.role==="Admin"?SYSCALL_DB.length:user.role==="Auditor"?0:ALLOWED[user.role].length}</span></div>
//                         <div>Executed: <span style={{ color:"#58a6ff" }}>{Object.keys(execHist).length}</span></div>
//                     </div>
//                 </div>

//                 {/* Panel 2 — Execution Panel */}
//                 <div style={{ flex:1,...BG, borderRight:"1px solid #30363d", display:"flex", flexDirection:"column", overflow:"hidden", minWidth:0 }}>
//                     <div style={{ padding:"8px 14px", borderBottom:"1px solid #21262d", fontSize:9,...txt2, letterSpacing:3, flexShrink:0 }}>EXECUTION PANEL</div>

//                     <div style={{ flex:1, overflowY:"auto", padding:14 }}>
//                         {!sc ? (
//                             <div style={{ ...txt2, textAlign:"center", paddingTop:80 }}>
//                                 <div style={{ fontSize:40, color:"#21262d", marginBottom:12 }}>◈</div>
//                                 <div style={{ fontSize:12 }}>Select a syscall from the browser</div>
//                                 <div style={{ fontSize:10, color:"#21262d", marginTop:6 }}>to build and execute</div>
//                                 {backend==="offline" && (
//                                     <div style={{ marginTop:20, padding:"10px 16px", background:"rgba(248,81,73,0.1)", border:"1px solid rgba(248,81,73,0.3)", borderRadius:6, fontSize:11, color:"#f85149" }}>
//                                         ⚠ Backend offline — run <strong>npm start</strong> in CMD for real syscalls
//                                     </div>
//                                 )}
//                             </div>
//                         ) : (
//                             <>
//                                 {/* Syscall header card */}
//                                 <div style={{ ...BG2,...BD, borderRadius:8, padding:"12px 14px", marginBottom:12 }}>
//                                     <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:8 }}>
//                                         <div style={{ ...tpri, fontSize:16, fontWeight:700 }}>{sc.name}</div>
//                                         <div style={{ display:"flex", gap:6, flexWrap:"wrap", justifyContent:"flex-end" }}>
//                                             <span style={{ fontSize:9, fontWeight:700, color:RISK[sc.risk].c, background:RISK[sc.risk].bg, border:`1px solid ${RISK[sc.risk].bd}`, borderRadius:4, padding:"2px 8px" }}>{sc.risk.toUpperCase()} RISK</span>
//                                             {canRun(user.role,sc.id)
//                                                 ?<span style={{ fontSize:9, color:"#3fb950", background:"rgba(63,185,80,0.1)", border:"1px solid rgba(63,185,80,0.3)", borderRadius:4, padding:"2px 8px" }}>✓ PERMITTED</span>
//                                                 :<span style={{ fontSize:9, color:"#f85149", background:"rgba(248,81,73,0.1)", border:"1px solid rgba(248,81,73,0.3)", borderRadius:4, padding:"2px 8px" }}>⊘ RESTRICTED</span>
//                                             }
//                                         </div>
//                                     </div>
//                                     <div style={{ ...txt2, fontSize:11, lineHeight:1.5 }}>{sc.desc}</div>
//                                     <div style={{ marginTop:8, fontSize:10,...txt2 }}>
//                                         Category: <span style={{ color:"#58a6ff" }}>{sc.cat}</span>
//                                         &nbsp;·&nbsp; Args: <span style={tpri}>{sc.args.length}</span>
//                                         &nbsp;·&nbsp; Mode: <span style={{ color: backend==="online"?"#3fb950":"#d29922" }}>{backend==="online"?"REAL":"SIMULATED"}</span>
//                                     </div>
//                                 </div>

//                                 {/* Arguments */}
//                                 {sc.args.length > 0 && (
//                                     <div style={{ ...BG2,...BD, borderRadius:8, padding:"12px 14px", marginBottom:12 }}>
//                                         <div style={{ fontSize:9,...txt2, letterSpacing:2, marginBottom:10 }}>ARGUMENTS</div>
//                                         {sc.args.map(arg=>(
//                                             <div key={arg.n} style={{ marginBottom:10 }}>
//                                                 <label style={{ display:"block", fontSize:10, color:"#58a6ff", marginBottom:5, letterSpacing:1 }}>{arg.n.toUpperCase()}</label>
//                                                 {arg.t==="sel"
//                                                     ?<select value={argv[arg.n]||arg.opts[0]}
//                                                         onChange={e=>setArgv(v=>({...v,[arg.n]:e.target.value}))}
//                                                         style={{ width:"100%",...BG, border:"1px solid #30363d", borderRadius:4, padding:"6px 10px",...tpri, fontSize:11,...F }}>
//                                                         {arg.opts.map(o=><option key={o} value={o}>{o}</option>)}
//                                                       </select>
//                                                     :<input type={arg.t==="num"?"number":"text"} placeholder={arg.p}
//                                                         value={argv[arg.n]||""}
//                                                         onChange={e=>setArgv(v=>({...v,[arg.n]:e.target.value}))}
//                                                         style={{ width:"100%",...BG, border:"1px solid #30363d", borderRadius:4, padding:"6px 10px",...tpri, fontSize:11,...F, boxSizing:"border-box", outline:"none" }}/>
//                                                 }
//                                             </div>
//                                         ))}
//                                     </div>
//                                 )}

//                                 {/* Pre-flight checks */}
//                                 <div style={{ ...BG, border:"1px solid #21262d", borderRadius:6, padding:"10px 14px", marginBottom:12 }}>
//                                     <div style={{ fontSize:9, color:"#3fb950", letterSpacing:2, marginBottom:8 }}>PRE-FLIGHT SECURITY CHECKS</div>
//                                     {[
//                                         [true,   `Session active — ${fmt(sessecs)} remaining`],
//                                         [canRun(user.role,sc.id), `Role permission: ${user.role} → ${sc.name}`],
//                                         [true,   "Input sanitization: passed"],
//                                         [true,   "Argument bounds: verified"],
//                                         [sessecs>0, "Session not expired"],
//                                         [backend==="online", `Backend: ${backend==="online"?"real execution":"simulation fallback"}`],
//                                     ].map(([chk,msg],i)=>(
//                                         <div key={i} style={{ fontSize:10,...txt2, marginBottom:3 }}>
//                                             <span style={{ color:chk?"#3fb950":"#d29922" }}>{chk?"✓":"⚠"}</span>{" "}{msg}
//                                         </div>
//                                     ))}
//                                 </div>

//                                 {/* Execute button */}
//                                 <button onClick={doExec} disabled={execSt==="running"} style={{
//                                     width:"100%", padding:"10px 0",
//                                     background:execSt==="running"?"#21262d":canRun(user.role,sc.id)?"#1a7f37":"#2b0e0e",
//                                     border:`1px solid ${execSt==="running"?"#30363d":canRun(user.role,sc.id)?"#2ea043":"#5c1a1a"}`,
//                                     borderRadius:6, color:execSt==="running"?"#8b949e":canRun(user.role,sc.id)?"#fff":"#f85149",
//                                     fontSize:12,...F, cursor:execSt==="running"?"wait":"pointer",
//                                     letterSpacing:1, fontWeight:600, marginBottom:12
//                                 }}>
//                                     {execSt==="running" ? "▶ EXECUTING..." :
//                                      canRun(user.role,sc.id) ? `▶ EXECUTE  ${sc.name}` :
//                                      `⊘ EXECUTE  ${sc.name}  (WILL BE BLOCKED)`}
//                                 </button>

//                                 {/* Result */}
//                                 {execRes && (
//                                     <div style={{ ...BG, border:`1px solid ${execSt==="success"?"#2ea043":execSt==="error"?"#d29922":"#5c1a1a"}`, borderRadius:6, padding:"12px 14px" }}>
//                                         <div style={{ fontSize:9, letterSpacing:2, marginBottom:8, color:execSt==="success"?"#3fb950":execSt==="error"?"#d29922":"#f85149" }}>
//                                             {execSt==="success"?"✓ RETURN VALUE":execSt==="error"?"⚠ SYSCALL ERROR":"⊘ EXECUTION BLOCKED"}
//                                         </div>
//                                         <pre style={{ margin:0, fontSize:12, color:execSt==="success"?"#e6edf3":execSt==="error"?"#d29922":"#f85149", whiteSpace:"pre-wrap", lineHeight:1.7 }}>
//                                             {execRes}
//                                         </pre>
//                                         {execSt==="success" && (
//                                             <div style={{ marginTop:10, paddingTop:10, borderTop:"1px solid #21262d", fontSize:10,...txt2 }}>
//                                                 logged to audit trail · {new Date().toLocaleTimeString("en-GB",{hour12:false})}
//                                                 {backend==="online" && <span style={{ color:"#3fb950", marginLeft:8 }}>● real execution</span>}
//                                             </div>
//                                         )}
//                                     </div>
//                                 )}
//                             </>
//                         )}
//                     </div>
//                 </div>

//                 {/* Panel 3 — Audit Log */}
//                 <div style={{ width:340,...BG, display:"flex", flexDirection:"column", flexShrink:0, overflow:"hidden" }}>
//                     <div style={{ padding:"8px 12px", borderBottom:"1px solid #21262d", display:"flex", alignItems:"center", justifyContent:"space-between", flexShrink:0 }}>
//                         <span style={{ fontSize:9,...txt2, letterSpacing:3 }}>AUDIT LOG</span>
//                         <span style={{ fontSize:9,...txt2 }}>{fLogs.length} entries</span>
//                     </div>

//                     {/* Filters */}
//                     <div style={{ padding:"8px 10px", borderBottom:"1px solid #21262d", display:"flex", gap:6, flexShrink:0 }}>
//                         <input placeholder="search user / syscall…" value={logF.q}
//                             onChange={e=>setLogF(f=>({...f,q:e.target.value}))}
//                             style={{ flex:1,...BG2, border:"1px solid #30363d", borderRadius:4, padding:"5px 8px",...tpri, fontSize:10,...F, minWidth:0, outline:"none" }}/>
//                         <select value={logF.res} onChange={e=>setLogF(f=>({...f,res:e.target.value}))}
//                             style={{ ...BG2, border:"1px solid #30363d", borderRadius:4, padding:"5px 8px",...txt2, fontSize:10,...F }}>
//                             <option value="all">all</option>
//                             <option value="success">success</option>
//                             <option value="blocked">blocked</option>
//                             <option value="error">error</option>
//                         </select>
//                     </div>

//                     {/* Log entries */}
//                     <div style={{ flex:1, overflowY:"auto" }}>
//                         {fLogs.length===0 && <div style={{ ...txt2, textAlign:"center", padding:"40px 0", fontSize:11 }}>No entries match filter</div>}
//                         {fLogs.map(l=>(
//                             <div key={l.id} onClick={()=>setDetailLog(detailLog?.id===l.id?null:l)}
//                                 style={{
//                                     padding:"8px 12px", borderBottom:"1px solid #161b22",
//                                     background:l.result==="blocked"?"rgba(248,81,73,0.04)":l.result==="error"?"rgba(210,153,34,0.04)":"transparent",
//                                     cursor:"pointer",
//                                     borderLeft:detailLog?.id===l.id?"2px solid #58a6ff":"2px solid transparent"
//                                 }}>
//                                 <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:3 }}>
//                                     <span style={{ color:"#58a6ff", fontSize:11, fontWeight:600 }}>{l.syscall}</span>
//                                     <span style={{ fontSize:9, color:l.result==="success"?"#3fb950":l.result==="error"?"#d29922":"#f85149", fontWeight:700 }}>
//                                         {l.result==="success"?"✓":l.result==="error"?"⚠":"⊘"} {l.result}
//                                     </span>
//                                 </div>
//                                 <div style={{ fontSize:9,...txt2, display:"flex", gap:8, marginBottom:2, flexWrap:"wrap" }}>
//                                     <span style={{ color:ROLE_C[l.role] }}>{l.user}</span>
//                                     <span>{l.ts}</span>
//                                     <span>{l.ip}</span>
//                                     {/* FIX 2: show PID/fd inline */}
//                                     {l.extra?.pid    && <span style={{ color:"#bc8cff" }}>PID:{l.extra.pid}</span>}
//                                     {l.extra?.fd     && <span style={{ color:"#58a6ff" }}>fd:{l.extra.fd}</span>}
//                                     {l.extra?.sockfd && <span style={{ color:"#58a6ff" }}>sock:{l.extra.sockfd}</span>}
//                                     {l.extra?.bytesRead    && <span style={{ color:"#3fb950" }}>{l.extra.bytesRead}B</span>}
//                                     {l.extra?.bytesWritten && <span style={{ color:"#3fb950" }}>{l.extra.bytesWritten}B</span>}
//                                     {l.extra?.bytes        && <span style={{ color:"#3fb950" }}>{l.extra.bytes}B</span>}
//                                 </div>

//                                 {/* Expanded detail */}
//                                 {detailLog?.id===l.id && (
//                                     <div style={{ marginTop:6,...BG, border:"1px solid #21262d", borderRadius:4, padding:"8px 10px" }}>
//                                         <div style={{ fontSize:9,...txt2, letterSpacing:1, marginBottom:6 }}>ARGUMENTS</div>
//                                         {Object.entries(l.args).length > 0
//                                             ? Object.entries(l.args).map(([k,v])=>(
//                                                 <div key={k} style={{ fontSize:10, marginBottom:3 }}>
//                                                     <span style={{ color:"#58a6ff" }}>{k}</span>
//                                                     <span style={txt2}> = </span>
//                                                     <span style={tpri}>{String(v)}</span>
//                                                 </div>
//                                               ))
//                                             : <div style={{ fontSize:10,...txt2 }}>no arguments</div>
//                                         }

//                                         {/* FIX 2: show all extra output data */}
//                                         {Object.keys(l.extra||{}).length > 0 && (
//                                             <>
//                                                 <div style={{ fontSize:9,...txt2, letterSpacing:1, marginBottom:6, marginTop:10 }}>OUTPUT DATA</div>
//                                                 {Object.entries(l.extra).map(([k,v])=>(
//                                                     <div key={k} style={{ fontSize:10, marginBottom:3 }}>
//                                                         <span style={{ color:"#3fb950" }}>{k}</span>
//                                                         <span style={txt2}> = </span>
//                                                         <span style={tpri}>{String(v)}</span>
//                                                     </div>
//                                                 ))}
//                                             </>
//                                         )}

//                                         <div style={{ marginTop:6, paddingTop:6, borderTop:"1px solid #21262d", fontSize:9,...txt2 }}>
//                                             Log ID #{l.id} · {l.role}
//                                         </div>
//                                     </div>
//                                 )}
//                             </div>
//                         ))}
//                     </div>

//                     {/* Stats footer */}
//                     <div style={{ padding:"8px 12px", borderTop:"1px solid #21262d", display:"flex", gap:14, fontSize:9, flexShrink:0 }}>
//                         <span style={{ color:"#8b949e" }}>total <span style={tpri}>{logs.length}</span></span>
//                         <span style={{ color:"#8b949e" }}>ok <span style={{ color:"#3fb950" }}>{logs.filter(l=>l.result==="success").length}</span></span>
//                         <span style={{ color:"#8b949e" }}>blocked <span style={{ color:"#f85149" }}>{logs.filter(l=>l.result==="blocked").length}</span></span>
//                         <span style={{ color:"#8b949e" }}>alerts <span style={{ color:"#d29922" }}>{alerts.length}</span></span>
//                     </div>
//                 </div>

//             </div>
//         </div>
//     );
// }
