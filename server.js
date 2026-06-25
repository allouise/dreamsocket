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
/* const originalLog = console.log; */

let allowedOriginsCache = {};
const allowedOriginsPath = path.join(__dirname, "allowed-origins.json");
function loadAllowedOrigins() {
    try {
        const data = fs.readFileSync(
            allowedOriginsPath,
            "utf-8"
        );
        const parsed = JSON.parse(data);
        const normalized = {};

        for (const origin in parsed) {
            normalized[normalizeOrigin(origin)] = parsed[origin];
        }

        allowedOriginsCache = normalized;
        console.log("Allowed origins reloaded");
    } catch (err) {
        console.error("Failed to load origins:", err);
        if (!Object.keys(allowedOriginsCache).length) {
            allowedOriginsCache = {};
        }
    }
}

/* Initial Load */
loadAllowedOrigins();

/* Auto Reload When File Changes */
fs.watchFile(allowedOriginsPath, { interval: 1000 }, () => {
    console.log("allowed-origins.json changed");
    loadAllowedOrigins();
});

const io = new Server(server, {
    cors: {
        origin: (origin, callback) => {
            const allowed = Object.keys(allowedOriginsCache);
    
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
/* console.log("ALL ENV:", process.env);
console.log("ENV PORT:", process.env.PORT); */
const PORT = process.env.PORT || 3000;
server.listen(PORT, "0.0.0.0", () => {
    /* console.log("Socket server running on Passenger port:", PORT); */
});

console.log = (...args) => {
    const message = args.join(" ");
    writeLog(message);
    /* originalLog.apply(console, args); */
};

console.error = (...args) => {
    const message = args.join(" ");
    writeLog("ERROR: " + message);
    /* originalLog.apply(console, args); */
};

function normalizeOrigin(origin) {
    return origin?.replace(/\/$/, "");
}

function writeLog(message) {
    const timestamp = new Date().toISOString();
    fs.appendFile( logFile, `[${timestamp}] ${message}\n`,
        (err) => {
            /* if (err) {
                originalLog("Log write failed:", err);
            } */
        }
    );
}

function validateToken(site, token) {
    const allowedOrigins = allowedOriginsCache;
    const siteConfig = allowedOrigins[site];
    if (!siteConfig?.secret) return false;

    const combinedSecret = siteConfig.secret;
    const expected = crypto
        .createHmac("sha256", combinedSecret)
        .update(site)
        .digest("hex");

    return token === expected;
}

function getActiveSessions(site) {
    return Object.entries(sessions[site] || {}).map(([session_id, data]) => ({
        session_id,
        visitor_name: data.visitor_name || session_id,
        active: data.active ?? false
    }));
}
function emitSupportStatus(site) {
    io.to(site).emit("support-status", {
        online: supportAgents[site]?.size > 0
    });
}

io.engine.on("connection_error", (err) => {
    console.error("ENGINE ERROR:", err.req, err.code, err.message, err.context);
});

/* ========================
 * State
 * Sessions = { site: { session_id: { visitor, admin } } }
 * supportAgents = { site: Map() }
 * ======================== */
let sessions = {};
let supportAgents = {};

/* ========================
 * Authenticate
 * ======================== */
io.use((socket, next) => {
    const { token, site } = socket.handshake.auth || {};
    const origin = normalizeOrigin(socket.handshake.headers.origin);
    const allowedOrigins = allowedOriginsCache;
    
    /* console.log("Incoming origin:", origin); */

    if (!origin || !allowedOrigins[origin]) {
        console.error("Blocked origin:", origin);
        return next(new Error("Origin not allowed"));
    }

    if (!site || !token || !validateToken(site, token)) {
        console.error("Unauthorized:", site);
        return next(new Error("Unauthorized"));
    }

    /* console.log("Allowed:", origin); */
    socket.site = site;
    next();
});

/* ========================
 * Socket logic
 * ======================== */
io.on("connection", (socket) => {
    const site = socket.site;
    socket.join(site);
    /* console.log(`Client Connected: ${socket.id} (site: ${site})`); */

    /* ========================
     * SUPPORT STATUS
     * ======================== */
    socket.emit("support-status", {
        online: supportAgents[site]?.size > 0
    });
    
    socket.on("register-support", () => {
        supportAgents[site] = supportAgents[site] || new Map();
        supportAgents[site].set(socket.id, true);
        emitSupportStatus(site);
        /* console.log(`site: ${site} | Support Registered | total: ${supportAgents[site]?.size}`); */
    });

    socket.on("unregister-support", () => {
        supportAgents[site]?.delete(socket.id);
        emitSupportStatus(site);
        /* console.log(`site: ${site} | Support Unregistered:`, supportAgents[site]?.size); */
    });
    
    /* ========================
     * VISITOR JOIN
     * accepts { session_id, visitor_name }
     * ======================== */
    socket.on("visitor-join", ({ session_id, visitor_name }) => {
        sessions[site] = sessions[site] || {};
        sessions[site][session_id] = sessions[site][session_id] || { messages: [] }; 

        const session = sessions[site][session_id];
        session.visitors = session.visitors || new Set();
        session.visitors.add(socket);
        session.active = true;

        if (visitor_name?.trim()) {
            session.visitor_name = visitor_name.trim();
        } else if (!session.visitor_name) {
            session.visitor_name = session_id;
        }

        if (session.messages?.length) {
            session.messages?.forEach(msg => socket.emit("receive-message", msg));
        }

        const name = session.visitor_name;
        io.to(site).emit("new-session", { session_id, visitor_name: name });
        io.to(site).emit("active-sessions", getActiveSessions(site));
        /* console.log(`site: ${site} | Visitor Joined | session: ${session_id} | name: ${name}`); */
    });

    /* ========================
     * ADMIN JOINS SESSION
     * ======================== */
    socket.on("join-session", ({ session_id }) => {
        sessions[site] = sessions[site] || {};
        sessions[site][session_id] = sessions[site][session_id] || {};
        sessions[site][session_id].admin = socket;
        /* console.log(`site: ${site} | Admin Joined Session:`, session_id); */
    });

    /* ========================
     * MESSAGES
     * ======================== */
    socket.on("send-message", (data) => {
        const { session_id, message, sender } = data;
        const session = sessions[site]?.[session_id];
        if (!session) return;

        if (sender === "admin") {
            const msg = { ...data };
            session.messages = session.messages || [];
            if (session.visitors && session.visitors.size > 0) {
                session.visitors.forEach(v => {
                    v.emit("receive-message", msg);
                });
            } else {
                session.messages.push(msg);
            }
        }

        if (sender === "visitor" && session.admin) {
            session.admin.emit("receive-message", data);
        }
    });

    /* ========================
     * ACTIVE SESSIONS REQUEST
     * Returns array of { session_id, visitor_name }
     * ======================== */
    socket.on("get-active-sessions", () => {
        socket.emit("active-sessions", getActiveSessions(site));
    });

    /* ========================
     * DISCONNECT
     * ======================== */
    socket.on("disconnect", () => {
        supportAgents[site]?.delete(socket.id);
        if (sessions[site]) {
            Object.keys(sessions[site]).forEach(sid => {
                const session = sessions[site][sid];
                if (session?.visitors?.has(socket)) {
                    session.visitors.delete(socket);

                    // Only mark inactive if ALL tabs are closed
                    if (session.visitors.size === 0) {
                        session.active = false;
                    }
                }
                if (session?.admin === socket) {
                    session.admin = null;
                }
            });
        }
        io.to(site).emit("support-status", {
            online: supportAgents[site]?.size > 0
        });
        io.to(site).emit("active-sessions", getActiveSessions(site));
        /* console.log(`site: ${site} | Disconnected:`, socket.id); */
    });

    /* ========================
     * GUEST RESTARTS CHAT BACK TO BOT
     * ======================== */
    socket.on("restarted-leave", ({ session_id }) => {
        if (sessions[site]?.[session_id]) {
            delete sessions[site][session_id];
        }
        io.to(site).emit("active-sessions", getActiveSessions(site));
        /* console.log(`site: ${site} | Visitor Left | session: ${session_id}`); */
    });
});
module.exports = app;

/* ========================
 * Home
 * ======================== */
app.get("/", (req, res) => {
    res.send(`
    <html>
    <head>
        <title>Dreamdesk Socket</title>
        <style>
        body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #121212; font-family: 'Arial', sans-serif; } .shadow-dance-text { font-size: 4rem; color: #fff; text-shadow: 5px 5px 0 #5cedff, 10px 10px 0 #00d4ff; animation: shadow-dance 2s infinite; } @keyframes shadow-dance { 0%, 100% { text-shadow: 5px 5px 0 #5cedff, 10px 10px 0 #00d4ff; } 50% { text-shadow: -5px -5px 0 #00d4ff, -10px -10px 0 #5cedff; } }
        </style>
    </head>
    <body>
    <div class="shadow-dance-container"><h1 class="shadow-dance-text">Dream Socket</h1></div>
    </body>
    </html>
    `);
});

/* ========================
 * Health
 * ======================== */
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

/* ========================
 * Get Quick Status
 * ======================== */
app.get("/status", (req, res) => {
    const site = req.query.site;
    const token = req.query.token;

    if (!site || !token) {
        return res.status(400).json({ running: false, error: "Missing site or token" });
    }

    const allowedOrigins = allowedOriginsCache;
    const siteData = allowedOrigins[site];
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