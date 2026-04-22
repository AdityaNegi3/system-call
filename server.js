import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import { spawn, exec } from "child_process";
import { createServer, Socket } from "net";
import os from "os";

const app = express();
app.use(cors());
app.use(express.json());

// ── Working directory for file syscalls ──────────────────────────
const WORK_DIR = path.join(os.tmpdir(), "syscall-guardian");
if (!fs.existsSync(WORK_DIR)) fs.mkdirSync(WORK_DIR, { recursive: true });

// ── In-memory state ──────────────────────────────────────────────
const openFiles   = new Map(); // fd  → { winPath, linuxPath, flags }
const openProcs   = new Map(); // pid → child process
let fdCounter     = 3;         // 0=stdin 1=stdout 2=stderr
let sockfdCounter = 4;

// ── Helper: map Linux paths → temp dir ──────────────────────────
function mapPath(linuxPath) {
    if (!linuxPath || linuxPath === "NULL") return path.join(WORK_DIR, "default.txt");
    const base = path.basename(linuxPath) || "file.txt";
    return path.join(WORK_DIR, base);
}

function ok(result, data = {})  { return { success: true,  result, data }; }
function err(result, data = {}) { return { success: false, result, data }; }

// ── Health check ─────────────────────────────────────────────────
app.get("/health", (_req, res) => res.json({ status: "online", pid: process.pid }));

// ════════════════════════════════════════════════════════════════
//  FILE I/O
// ════════════════════════════════════════════════════════════════

app.post("/syscall/open", (req, res) => {
    const { pathname = "/tmp/file.txt", flags = "O_RDONLY" } = req.body;
    try {
        const winPath = mapPath(pathname);
        // Create file if it doesn't exist yet
        if (!fs.existsSync(winPath)) {
            fs.writeFileSync(winPath,
                `# Simulated file: ${pathname}\n# Created by SYSCALL GUARDIAN\n# Windows path: ${winPath}\n`);
        }
        const fd = ++fdCounter;
        openFiles.set(fd, { winPath, linuxPath: pathname, flags });
        res.json(ok(
            `fd = ${fd}\n→ mapped to: ${winPath}`,
            { fd, linuxPath: pathname, winPath, flags }
        ));
    } catch (e) {
        res.json(err(`ENOENT: cannot open '${pathname}': ${e.message}`));
    }
});

app.post("/syscall/read", (req, res) => {
    const { fd = 3, count = 1024 } = req.body;
    const fdNum = parseInt(fd);
    const file  = openFiles.get(fdNum);
    try {
        let content = "";
        if (file && fs.existsSync(file.winPath)) {
            const raw = fs.readFileSync(file.winPath, "utf8");
            content   = raw.slice(0, parseInt(count));
        } else {
            content = `[fd ${fdNum} not open — use open() first]`;
        }
        const bytes = Buffer.byteLength(content, "utf8");
        const preview = content.slice(0, 80).replace(/\n/g, "↵");
        res.json(ok(
            `${bytes} bytes read\n→ "${preview}${content.length > 80 ? "…" : ""}"`,
            { bytesRead: bytes, fd: fdNum, preview }
        ));
    } catch (e) {
        res.json(err(`EIO: read failed: ${e.message}`, { fd: fdNum }));
    }
});

app.post("/syscall/write", (req, res) => {
    const { fd = 1, buf = "hello", count } = req.body;
    const fdNum = parseInt(fd);
    const data  = String(buf);
    const bytes = parseInt(count) || Buffer.byteLength(data, "utf8");
    try {
        const file = openFiles.get(fdNum);
        if (file) {
            fs.appendFileSync(file.winPath, data + "\n", "utf8");
        }
        res.json(ok(
            `${bytes} bytes written${file ? `\n→ appended to: ${file.winPath}` : ""}`,
            { bytesWritten: bytes, fd: fdNum, buf: data }
        ));
    } catch (e) {
        res.json(err(`EIO: write failed: ${e.message}`, { fd: fdNum }));
    }
});

app.post("/syscall/close", (req, res) => {
    const { fd = 3 } = req.body;
    const fdNum  = parseInt(fd);
    const existed = openFiles.has(fdNum);
    openFiles.delete(fdNum);
    res.json(ok(
        `0  (fd ${fdNum} ${existed ? "closed" : "was not open"})`,
        { fd: fdNum, wasOpen: existed }
    ));
});

app.post("/syscall/unlink", (req, res) => {
    const { pathname = "/tmp/test.txt" } = req.body;
    const winPath = mapPath(pathname);
    try {
        if (fs.existsSync(winPath)) {
            fs.unlinkSync(winPath);
            res.json(ok(`0  (removed: ${pathname})\n→ deleted: ${winPath}`, { path: pathname, winPath }));
        } else {
            res.json(err(`ENOENT: file not found: ${pathname}\n(use open() to create it first)`, {}));
        }
    } catch (e) {
        res.json(err(`EACCES: ${e.message}`, {}));
    }
});

// ════════════════════════════════════════════════════════════════
//  PROCESS
// ════════════════════════════════════════════════════════════════

app.post("/syscall/fork", (_req, res) => {
    try {
        // Spawn a real short-lived child process
        const child = spawn(process.execPath, ["-e", "setTimeout(()=>{}, 5000)"], {
            detached: true,
            stdio:    "ignore",
        });
        const pid = child.pid;
        openProcs.set(pid, child);
        child.unref();
        res.json(ok(
            `child pid = ${pid}\nparent pid = ${process.pid}`,
            { pid, parentPid: process.pid }
        ));
    } catch (e) {
        res.json(err(`EAGAIN: fork failed: ${e.message}`));
    }
});

app.post("/syscall/execve", (req, res) => {
    const { filename = "/bin/ls", argv: argStr = "" } = req.body;
    // Map Linux commands → Windows equivalents
    const cmdMap = {
        "/bin/ls":     "dir",
        "/usr/bin/ls": "dir",
        "/bin/echo":   "echo",
        "/bin/cat":    "type",
        "/bin/pwd":    "cd",
        "/bin/date":   "date /t",
        "/bin/whoami": "whoami",
        "/bin/ps":     "tasklist",
    };
    const winCmd = cmdMap[filename] || "dir";
    const winArgs = argStr.replace(/-la/g, "/w").replace(/\/tmp/g, os.tmpdir());

    exec(`${winCmd} ${winArgs}`, { timeout: 4000, cwd: WORK_DIR }, (error, stdout) => {
        const output = (stdout || "").slice(0, 300).trim();
        res.json(ok(
            `0  (exec'd: ${filename})\n${output || "[no output]"}`,
            { filename, mappedCmd: `${winCmd} ${winArgs}`, outputPreview: output.slice(0, 100) }
        ));
    });
});

app.post("/syscall/kill", (req, res) => {
    const { pid, sig = "SIGTERM" } = req.body;
    const pidNum = parseInt(pid);
    try {
        if (openProcs.has(pidNum)) {
            process.kill(pidNum, "SIGTERM");
            openProcs.delete(pidNum);
            res.json(ok(`0  (signal ${sig} delivered to pid ${pidNum})`, { pid: pidNum, signal: sig }));
        } else {
            // Check if process exists at all
            try {
                process.kill(pidNum, 0);
                res.json(ok(`0  (signal ${sig} sent to pid ${pidNum})`, { pid: pidNum, signal: sig }));
            } catch {
                res.json(err(`ESRCH: No such process: ${pidNum}`, { pid: pidNum }));
            }
        }
    } catch (e) {
        res.json(err(`EPERM: ${e.message}`, { pid: pidNum }));
    }
});

app.post("/syscall/waitpid", (req, res) => {
    const { pid = -1, options = "0" } = req.body;
    const pidNum   = parseInt(pid);
    const isNohang = options === "WNOHANG";
    const pids     = [...openProcs.keys()];

    if (pidNum === -1 || isNohang) {
        if (pids.length > 0) {
            const found = pids[0];
            res.json(ok(`pid = ${found}, status = 0`, { pid: found, status: 0, flag: options }));
        } else {
            res.json(ok(`0  (${isNohang ? "WNOHANG: no child ready" : "no children to wait for"})`,
                { pid: 0, status: -1, flag: options }));
        }
    } else {
        res.json(ok(`pid = ${pidNum}, status = 0`, { pid: pidNum, status: 0, flag: options }));
    }
});

// ════════════════════════════════════════════════════════════════
//  NETWORK
// ════════════════════════════════════════════════════════════════

app.post("/syscall/socket", (req, res) => {
    const { domain = "AF_INET", type = "SOCK_STREAM" } = req.body;
    const sockfd = ++sockfdCounter;
    res.json(ok(`sockfd = ${sockfd}`, { sockfd, domain, type }));
});

app.post("/syscall/bind", (req, res) => {
    const { sockfd = 4, port = 8080, addr = "0.0.0.0" } = req.body;
    const portNum   = parseInt(port);
    const bindAddr  = addr === "0.0.0.0" ? "127.0.0.1" : addr;
    const server    = createServer();

    server.listen(portNum, bindAddr, () => {
        server.close(() => {
            res.json(ok(
                `0  (bound to ${addr}:${portNum})`,
                { sockfd: parseInt(sockfd), port: portNum, addr }
            ));
        });
    });
    server.on("error", (e) => {
        if (e.code === "EADDRINUSE") {
            res.json(err(`EADDRINUSE: port ${portNum} already in use`, { port: portNum }));
        } else {
            res.json(err(`ENETDOWN: ${e.message}`, {}));
        }
    });
});

app.post("/syscall/connect", (req, res) => {
    const { sockfd = 4, addr = "127.0.0.1", port = 80 } = req.body;
    const portNum = parseInt(port);
    const socket  = new Socket();
    socket.setTimeout(2500);

    socket.connect(portNum, addr, () => {
        socket.destroy();
        res.json(ok(`0  (connected to ${addr}:${portNum})`, { sockfd: parseInt(sockfd), addr, port: portNum, connected: true }));
    });
    socket.on("error", () => {
        res.json(ok(
            `0  (connect attempted → ${addr}:${portNum})\n[host unreachable — simulated success]`,
            { sockfd: parseInt(sockfd), addr, port: portNum, connected: false, note: "simulated" }
        ));
    });
    socket.on("timeout", () => {
        socket.destroy();
        res.json(ok(
            `ETIMEDOUT: connection to ${addr}:${portNum} timed out`,
            { sockfd: parseInt(sockfd), addr, port: portNum }
        ));
    });
});

app.post("/syscall/send", (req, res) => {
    const { sockfd = 4, buf = "", flags = "0" } = req.body;
    const data  = String(buf);
    const bytes = Buffer.byteLength(data, "utf8");
    res.json(ok(`${bytes} bytes sent`, { sockfd: parseInt(sockfd), bytes, buf: data, flags }));
});

app.post("/syscall/recv", (req, res) => {
    const { sockfd = 4, len = 4096, flags = "0" } = req.body;
    const bytes = Math.floor(Math.random() * parseInt(len));
    res.json(ok(`${bytes} bytes received`, { sockfd: parseInt(sockfd), bytes, maxLen: parseInt(len), flags }));
});

// ════════════════════════════════════════════════════════════════
//  MEMORY
// ════════════════════════════════════════════════════════════════

app.post("/syscall/mmap", (req, res) => {
    const { addr = "NULL", length = 4096, prot = "PROT_READ" } = req.body;
    const mem = process.memoryUsage();
    const mappedAddr = `0x${(BigInt(mem.heapUsed) + BigInt(Math.floor(Math.random() * 0xfffff))).toString(16).padStart(12, "0")}`;
    res.json(ok(mappedAddr, { addr: mappedAddr, length: parseInt(length), prot, heapUsedMB: (mem.heapUsed / 1024 / 1024).toFixed(1) }));
});

app.post("/syscall/mprotect", (req, res) => {
    const { addr, len = 4096, prot = "PROT_READ" } = req.body;
    res.json(ok(`0  (${addr} → ${prot})`, { addr, len: parseInt(len), prot }));
});

app.post("/syscall/brk", (_req, res) => {
    const mem = process.memoryUsage();
    const brk = `0x${mem.heapUsed.toString(16).padStart(12, "0")}`;
    res.json(ok(brk, { addr: brk, heapUsedBytes: mem.heapUsed, heapTotalBytes: mem.heapTotal }));
});

// ════════════════════════════════════════════════════════════════
//  SECURITY
// ════════════════════════════════════════════════════════════════

app.post("/syscall/setuid", (req, res) => {
    const { uid = 0 } = req.body;
    const currentUid = typeof process.getuid === "function" ? process.getuid() : "N/A (Windows)";
    res.json(ok(`0  (uid set to ${uid})`, { uid: parseInt(uid), previousUid: currentUid, platform: process.platform }));
});

app.post("/syscall/chmod", (req, res) => {
    const { pathname = "/etc/shadow", mode = "0644" } = req.body;
    const winPath = mapPath(pathname);
    try {
        if (fs.existsSync(winPath)) fs.chmodSync(winPath, parseInt(mode, 8));
        res.json(ok(`0  (mode ${mode} applied to ${pathname})`, { path: pathname, mode, winPath }));
    } catch {
        res.json(ok(`0  (mode ${mode} applied — simulated)`, { path: pathname, mode }));
    }
});

app.post("/syscall/chroot", (req, res) => {
    const { path: chrootPath = "/var/chroot" } = req.body;
    res.json(ok(`0  (root → ${chrootPath})`, { path: chrootPath, previousRoot: "/", platform: "linux-simulated" }));
});

// ── File list endpoint (show what's in WORK_DIR) ─────────────────
app.get("/files", (_req, res) => {
    try {
        const files = fs.readdirSync(WORK_DIR).map(f => {
            const fp   = path.join(WORK_DIR, f);
            const stat = fs.statSync(fp);
            return { name: f, size: stat.size, modified: stat.mtime };
        });
        res.json({ dir: WORK_DIR, files });
    } catch {
        res.json({ dir: WORK_DIR, files: [] });
    }
});

// ────────────────────────────────────────────────────────────────
const PORT = 3001;
app.listen(PORT, () => {
    console.log(`\n✅ SYSCALL GUARDIAN Backend — http://localhost:${PORT}`);
    console.log(`📁 Working directory: ${WORK_DIR}\n`);
});
