const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
app.set("trust proxy", 1);
const server = http.createServer(app);
const logFile = path.join(__dirname, "server.log");

let allowedOriginsCache = {};
const allowedOriginsPath = path.join(__dirname, "allowed-origins.json");

/* ========================
 * Cache & Utilities
 * ======================== */
function normalizeOrigin(origin) {
    if (!origin) return "";
    try {
        const parsed = new URL(origin);
        return parsed.origin;
    } catch {
        return origin.replace(/\/$/, "");
    }
}

function loadAllowedOrigins() {
    try {
        const data = fs.readFileSync(allowedOriginsPath, "utf-8");
        const parsed = JSON.parse(data);
        const normalized = {};

        for (const origin in parsed) {
            normalized[normalizeOrigin(origin)] = parsed[origin];
        }

        allowedOriginsCache = normalized;
        log("Allowed origins reloaded");
    } catch (err) {
        logError("Failed to load origins:", err);
        if (!Object.keys(allowedOriginsCache).length) {
            allowedOriginsCache = {};
        }
    }
}

/* Initial Load & File Watcher */
loadAllowedOrigins();
fs.watchFile(allowedOriginsPath, { interval: 1000 }, () => {
    log("allowed-origins.json changed", true);
    loadAllowedOrigins();
});

/* ========================
 * Socket.IO Configuration
 * ======================== */
const io = new Server(server, {
    transports: ["websocket", "polling"],
    cors: {
        origin: (origin, callback) => {
            const allowed = Object.keys(allowedOriginsCache);
            // Allow requests with no origin (like mobile apps, Postman, or server-to-server)
            if (!origin || allowed.includes(normalizeOrigin(origin))) {
                callback(null, true);
            } else {
                callback(new Error("Not allowed by CORS"));
            }
        },
        credentials: true
    },
    path: "/socket.io"
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, "0.0.0.0", () => {
    log("Socket server running on port:", PORT);
});

/* ========================
 * State Management
 * ======================== */
let sessions = {};        // { site: { session_id: { messages: [], active: bool, ... } } }
let supportAgents = {};   // { site: Set(socket.id) }

function validateToken(site, token) {
    const siteConfig = allowedOriginsCache[site];
    if (!siteConfig?.secret) return false;

    const expected = crypto
        .createHmac("sha256", siteConfig.secret)
        .update(site)
        .digest("hex");

    return token === expected;
}

function isValidSessionId(sessionId) {
    return (
        typeof sessionId === "string" &&
        sessionId.trim().length > 0 &&
        sessionId !== "null" &&
        sessionId !== "undefined"
    );
}

function getActiveSessions(site) {
    return Object.entries(sessions[site] || {}).map(([session_id, data]) => ({
        session_id,
        visitor_name: data.visitor_name || session_id,
        active: data.active ?? false,
        start_datetime: data.start_datetime,
        last_message_datetime: data.last_message_datetime
    }));
}

function emitActiveSessions(site) {
    io.to(`site:${site}`).emit("active-sessions", getActiveSessions(site));
}

function emitSupportStatus(site) {
    const isOnline = (supportAgents[site]?.size || 0) > 0;
    io.to(`site:${site}`).emit("support-status", { online: isOnline });
}

/* ========================
 * Logging Helpers
 * ======================== */
function log(...args) {
    let saveToFile = false;
    if (typeof args[args.length - 1] === "boolean") saveToFile = args.pop();
    console.log(...args);
    if (!saveToFile) return;

    const message = args.map(arg => (typeof arg === "object" ? JSON.stringify(arg) : String(arg))).join(" ");
    writeLog(message);
}

function logError(...args) {
    console.error(...args);
    const message = args.map(arg => (arg instanceof Error ? arg.stack : typeof arg === "object" ? JSON.stringify(arg) : String(arg))).join(" ");
    writeLog("ERROR: " + message);
}

function writeLog(message) {
    const timestamp = new Date().toISOString();
    fs.appendFile(logFile, `[${timestamp}] ${message}\n`, err => {
        if (err) process.stderr.write(`[${timestamp}] Failed to write log: ${err.message}\n`);
    });
}

io.engine.on("connection_error", (err) => {
    if (err.code === 1) return; // Transport closed code
    logError("ENGINE ERROR:", err.code, err.message, err.context);
});

/* ========================
 * Authentication Middleware
 * ======================== */
io.use((socket, next) => {
    const { token, site } = socket.handshake.auth || {};
    const rawOrigin = socket.handshake.headers.origin || socket.handshake.headers.referer;
    const origin = rawOrigin ? normalizeOrigin(rawOrigin) : null;

    // Check origin only if header is explicitly provided
    if (origin && !allowedOriginsCache[origin]) {
        logError("Blocked origin:", origin);
        return next(new Error("Origin not allowed"));
    }

    if (!site || !token || !validateToken(site, token)) {
        logError("Unauthorized site/token:", site);
        return next(new Error("Unauthorized"));
    }

    socket.site = site;
    next();
});

/* ========================
 * Socket Logic
 * ======================== */
io.on("connection", (socket) => {
    const site = socket.site;

    // Join site-wide room for site-level broadcasts
    socket.join(`site:${site}`);
    log("Client connected:", socket.id, "Site:", site);

    /* --- Support Status --- */
    socket.emit("support-status", {
        online: (supportAgents[site]?.size || 0) > 0
    });

    socket.on("register-support", () => {
        supportAgents[site] = supportAgents[site] || new Set();
        supportAgents[site].add(socket.id); // Store socket.id string (no memory leak)
        emitSupportStatus(site);
    });

    socket.on("unregister-support", () => {
        supportAgents[site]?.delete(socket.id);
        emitSupportStatus(site);
    });

    /* --- Visitor Join --- */
    socket.on("visitor-join", ({ session_id, visitor_name }) => {
        if (!isValidSessionId(session_id)) return;

        sessions[site] = sessions[site] || {};
        const isNewSession = !sessions[site][session_id];

        sessions[site][session_id] = sessions[site][session_id] || {
            messages: [],
            start_datetime: new Date().toISOString()
        };

        const session = sessions[site][session_id];
        session.active = true;
        if (!session.last_message_datetime) {
            session.last_message_datetime = session.start_datetime;
        }

        if (visitor_name?.trim()) {
            session.visitor_name = visitor_name.trim();
        } else if (!session.visitor_name) {
            session.visitor_name = session_id;
        }

        // Tag socket with session details & join room
        socket.sessionId = session_id;
        socket.join(`session:${site}:${session_id}`);

        // Replay history to newly joined/reconnected client
        if (session.messages?.length) {
            session.messages.forEach(msg => socket.emit("receive-message", msg));
        }

        io.to(`site:${site}`).emit("new-session", {
            session_id,
            visitor_name: session.visitor_name,
            start_datetime: session.start_datetime,
            last_message_datetime: session.last_message_datetime
        });

        emitActiveSessions(site);
    });

    /* --- Admin Join Session --- */
    socket.on("join-session", ({ session_id }) => {
        if (!isValidSessionId(session_id)) return;
        
        socket.sessionId = session_id;
        socket.join(`session:${site}:${session_id}`);
    });

    /* --- Messaging --- */
    socket.on("send-message", (data) => {
        const { session_id, message, sender } = data;
        const session = sessions[site]?.[session_id];
        if (!session) return;

        const now = new Date().toISOString();
        session.last_message_datetime = now;

        const msgPayload = { ...data, timestamp: now };

        // Append to session history buffer
        session.messages = session.messages || [];
        session.messages.push(msgPayload);

        // Broadcast to room (delivers to visitor & admin transparently)
        io.to(`session:${site}:${session_id}`).emit("receive-message", msgPayload);

        emitActiveSessions(site);
    });

    socket.on("get-active-sessions", () => {
        socket.emit("active-sessions", getActiveSessions(site));
    });

    /* --- End Chat --- */
    socket.on("end-chat", ({ session_id }) => {
        const room = `session:${site}:${session_id}`;
        io.to(room).emit("chat-ended");
        
        delete sessions[site]?.[session_id];
        emitActiveSessions(site);
    });

    /* --- Disconnect Handler --- */
    socket.on("disconnect", () => {
        // Clean up support agent tracking
        if (supportAgents[site]?.has(socket.id)) {
            supportAgents[site].delete(socket.id);
            emitSupportStatus(site);
        }

        // Check active count in visitor room to set active status accurately
        if (socket.sessionId && sessions[site]?.[socket.sessionId]) {
            const roomName = `session:${site}:${socket.sessionId}`;
            const roomSockets = io.sockets.adapter.rooms.get(roomName);
            
            // Mark session inactive if no sockets remain in room
            if (!roomSockets || roomSockets.size === 0) {
                sessions[site][socket.sessionId].active = false;
            }
        }

        emitActiveSessions(site);
    });
});

/* ========================
 * HTTP Routes
 * ======================== */
app.get("/", (req, res) => {
    res.send(`
    <html>
    <head>
        <title>Dreamdesk Socket</title>
        <style>
            body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #121212; font-family: sans-serif; } 
            .shadow-dance-text { font-size: 4rem; color: #fff; text-shadow: 5px 5px 0 #5cedff, 10px 10px 0 #00d4ff; }
        </style>
    </head>
    <body>
        <div class="shadow-dance-container"><h1 class="shadow-dance-text">Dream Socket</h1></div>
    </body>
    </html>
    `);
});

app.get("/health", (req, res) => {
    res.status(200).json({
        running: true,
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        memoryUsage: process.memoryUsage(),
        activeSessions: sessions ? Object.keys(sessions).length : 0,
        supportGroups: supportAgents ? Object.keys(supportAgents).length : 0
    });
});

app.get("/status", (req, res) => {
    const site = req.query.site;
    const token = req.query.token;

    if (!site || !token) {
        return res.status(400).json({ running: false, error: "Missing site or token" });
    }

    const siteData = allowedOriginsCache[site];
    if (!siteData) {
        return res.status(403).json({ running: false, error: "Site not allowed" });
    }

    const expectedToken = crypto
        .createHmac("sha256", siteData.secret)
        .update(site)
        .digest("hex");

    if (token !== expectedToken) {
        return res.status(403).json({ running: false, error: "Invalid token" });
    }

    res.json({ running: true, onlineSupport: Object.keys(sessions[site] || {}).length });
});

module.exports = app;