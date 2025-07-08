const { Client, LocalAuth, MessageMedia } = require('whatsapp-web.js');
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const QRCode = require('qrcode');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = './uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 16 * 1024 * 1024 } // 16MB limit
});

// Store WhatsApp clients
const clients = new Map();
const qrCodes = new Map();
const sessionStatus = new Map();

// User management
const users = new Map();
const messageQueues = new Map();

// Ensure directories exist
const sessionsDir = './sessions';
const dataDir = './data';
const usersFile = './data/users.json';

[sessionsDir, dataDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// Load users from file
function loadUsers() {
    try {
        if (fs.existsSync(usersFile)) {
            const userData = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
            userData.forEach(user => {
                users.set(user.username, user);
            });
        }
    } catch (error) {
        console.error('Error loading users:', error);
    }
}

// Save users to file
function saveUsers() {
    try {
        const userData = Array.from(users.values());
        fs.writeFileSync(usersFile, JSON.stringify(userData, null, 2));
    } catch (error) {
        console.error('Error saving users:', error);
    }
}

// Generate API key
function generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
}

// Generate user key
function generateUserKey() {
    return crypto.randomUUID();
}

// Authentication middleware
function authenticateUser(req, res, next) {
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['x-api-key'];

    if (!authHeader && !apiKey) {
        return res.status(401).json({
            success: false,
            message: 'No authentication provided'
        });
    }

    if (apiKey) {
        // API Key authentication
        const user = Array.from(users.values()).find(u => u.apiKey === apiKey);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid API key'
            });
        }
        req.user = user;
        return next();
    }

    // JWT authentication
    const token = authHeader?.split(' ')[1];
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'No token provided'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = users.get(decoded.username);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }
        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: 'Invalid token'
        });
    }
}

// Admin authentication middleware
function authenticateAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'No token provided'
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Admin access required'
            });
        }
        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: 'Invalid token'
        });
    }
}

// Message delay logic
class MessageQueue {
    constructor(sessionId, delayMs = 2000) {
        this.sessionId = sessionId;
        this.delayMs = delayMs;
        this.queue = [];
        this.isProcessing = false;
        this.lastMessageTime = 0;
    }

    async addMessage(messageData) {
        return new Promise((resolve, reject) => {
            this.queue.push({ ...messageData, resolve, reject });
            this.processQueue();
        });
    }

    async processQueue() {
        if (this.isProcessing || this.queue.length === 0) return;

        this.isProcessing = true;

        while (this.queue.length > 0) {
            const currentTime = Date.now();
            const timeSinceLastMessage = currentTime - this.lastMessageTime;

            if (timeSinceLastMessage < this.delayMs) {
                const waitTime = this.delayMs - timeSinceLastMessage;
                await new Promise(resolve => setTimeout(resolve, waitTime));
            }

            const messageData = this.queue.shift();

            try {
                const result = await this.sendMessage(messageData);
                this.lastMessageTime = Date.now();
                messageData.resolve(result);
            } catch (error) {
                messageData.reject(error);
            }
        }

        this.isProcessing = false;
    }

    async sendMessage(messageData) {
        const { sessionId, chatId, message, file } = messageData;
        const client = clients.get(sessionId);

        if (!client) {
            throw new Error('Session not found');
        }

        const status = sessionStatus.get(sessionId);
        if (status !== 'ready') {
            throw new Error('Session is not ready. Current status: ' + status);
        }

        let sentMessage;

        if (file) {
            const media = MessageMedia.fromFilePath(file.path);
            sentMessage = await client.sendMessage(chatId, media, { caption: message });
            fs.unlinkSync(file.path);
        } else {
            sentMessage = await client.sendMessage(chatId, message);
        }

        return {
            messageId: sentMessage.id._serialized,
            timestamp: new Date().toISOString(),
            hasFile: !!file
        };
    }

    setDelay(delayMs) {
        this.delayMs = delayMs;
    }
}

// Create WhatsApp client for a user
function createClient(sessionId, userId) {
    const client = new Client({
        authStrategy: new LocalAuth({
            clientId: `${userId}_${sessionId}`,
            dataPath: './sessions'
        }),
        puppeteer: {
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--no-first-run',
                '--no-zygote',
                '--disable-gpu'
            ]
        }
    });

    // QR Code generation
    client.on('qr', async (qr) => {
        console.log(`QR Code generated for session: ${sessionId}`);
        try {
            const qrCodeDataURL = await QRCode.toDataURL(qr);
            qrCodes.set(sessionId, qrCodeDataURL);
            sessionStatus.set(sessionId, 'qr_generated');
        } catch (error) {
            console.error('QR Code generation error:', error);
        }
    });

    // Client ready
    client.on('ready', async () => {
        console.log(`WhatsApp client ready for session: ${sessionId}`);
        sessionStatus.set(sessionId, 'ready');
        qrCodes.delete(sessionId);

        const info = client.info;
        const clientData = {
            number: info.wid.user,
            name: info.pushname,
            platform: info.platform,
            connectedAt: new Date().toISOString(),
            userId: userId
        };

        const clientInfo = JSON.stringify(clientData);
        fs.writeFileSync(`./sessions/${sessionId}_info.json`, clientInfo);

        // Initialize message queue for this session
        const user = Array.from(users.values()).find(u => u.username === userId);
        const delayMs = user?.messageDelay || 2000;
        messageQueues.set(sessionId, new MessageQueue(sessionId, delayMs));
    });

    client.on('authenticated', () => {
        console.log(`Authentication successful for session: ${sessionId}`);
        sessionStatus.set(sessionId, 'authenticated');
    });

    client.on('auth_failure', (message) => {
        console.error(`Authentication failed for session ${sessionId}:`, message);
        sessionStatus.set(sessionId, 'auth_failed');
    });

    client.on('disconnected', (reason) => {
        console.log(`Client disconnected for session ${sessionId}:`, reason);
        sessionStatus.set(sessionId, 'disconnected');
        messageQueues.delete(sessionId);
    });

    client.on('message', async (message) => {
        console.log(`Message received in session ${sessionId}:`, message.body);

        if (message.body.toLowerCase() === 'ping') {
            await message.reply('Pong from API!');
        }
    });

    return client;
}

// Initialize client for session
async function initializeSession(sessionId, userId) {
    const fullSessionId = `${userId}_${sessionId}`;

    if (clients.has(fullSessionId)) {
        return { success: false, message: 'Session already exists' };
    }

    try {
        const client = createClient(fullSessionId, userId);
        clients.set(fullSessionId, client);
        sessionStatus.set(fullSessionId, 'initializing');

        await client.initialize();

        return { success: true, message: 'Session initialized successfully' };
    } catch (error) {
        console.error('Error initializing session:', error);
        return { success: false, message: 'Failed to initialize session' };
    }
}

// Load users on startup
loadUsers();

// API Routes

// Admin login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
            const token = jwt.sign(
                { username: ADMIN_USERNAME, role: 'admin' },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({
                success: true,
                token,
                message: 'Admin login successful'
            });
        } else {
            res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Login failed'
        });
    }
});

// Create user (Admin only)
app.post('/api/admin/create-user', authenticateAdmin, async (req, res) => {
    try {
        const { username, password, messageDelay = 2000, maxSessions = 5 } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        if (users.has(username)) {
            return res.status(400).json({
                success: false,
                message: 'User already exists'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userKey = generateUserKey();
        const apiKey = generateApiKey();

        const newUser = {
            username,
            password: hashedPassword,
            userKey,
            apiKey,
            messageDelay,
            maxSessions,
            createdAt: new Date().toISOString(),
            isActive: true
        };

        users.set(username, newUser);
        saveUsers();

        res.json({
            success: true,
            message: 'User created successfully',
            user: {
                username,
                userKey,
                apiKey,
                messageDelay,
                maxSessions
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to create user'
        });
    }
});

// Get all users (Admin only)
app.get('/api/admin/users', authenticateAdmin, (req, res) => {
    try {
        const userList = Array.from(users.values()).map(user => ({
            username: user.username,
            userKey: user.userKey,
            apiKey: user.apiKey,
            messageDelay: user.messageDelay,
            maxSessions: user.maxSessions,
            createdAt: user.createdAt,
            isActive: user.isActive
        }));

        res.json({
            success: true,
            users: userList
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users'
        });
    }
});

// User login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        const user = users.get(username);
        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const token = jwt.sign(
            { username: user.username, role: 'user' },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            userKey: user.userKey,
            apiKey: user.apiKey,
            messageDelay: user.messageDelay,
            maxSessions: user.maxSessions,
            message: 'Login successful'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Login failed'
        });
    }
});

// Create new session (User)
app.post('/api/create-session', authenticateUser, async (req, res) => {
    try {
        const { sessionId } = req.body;
        const user = req.user;

        if (!sessionId) {
            return res.status(400).json({
                success: false,
                message: 'Session ID is required'
            });
        }

        // Check session limit
        const userSessions = Array.from(clients.keys()).filter(key =>
            key.startsWith(user.username + '_')
        );

        if (userSessions.length >= user.maxSessions) {
            return res.status(400).json({
                success: false,
                message: `Maximum sessions limit reached (${user.maxSessions})`
            });
        }

        const result = await initializeSession(sessionId, user.username);
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get user sessions
app.get('/api/sessions', authenticateUser, (req, res) => {
    try {
        const user = req.user;
        const sessions = [];

        for (const [sessionId, client] of clients) {
            if (sessionId.startsWith(user.username + '_')) {
                const cleanSessionId = sessionId.replace(user.username + '_', '');
                const status = sessionStatus.get(sessionId) || 'unknown';
                const qrCode = qrCodes.get(sessionId) || null;

                let info = null;
                try {
                    const infoPath = `./sessions/${sessionId}_info.json`;
                    if (fs.existsSync(infoPath)) {
                        info = JSON.parse(fs.readFileSync(infoPath, 'utf8'));
                    }
                } catch (error) {
                    console.error('Error reading session info:', error);
                }

                sessions.push({
                    sessionId: cleanSessionId,
                    status,
                    qrCode,
                    info,
                    messageDelay: user.messageDelay
                });
            }
        }

        res.json({ success: true, sessions });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error fetching sessions'
        });
    }
});

// Send message with delay queue
app.post('/api/send-message', authenticateUser, upload.single('file'), async (req, res) => {
    try {
        const { sessionId, number, message } = req.body;
        const file = req.file;
        const user = req.user;

        if (!sessionId || !number || !message) {
            return res.status(400).json({
                success: false,
                message: 'Session ID, number, and message are required'
            });
        }

        const fullSessionId = `${user.username}_${sessionId}`;
        const client = clients.get(fullSessionId);

        if (!client) {
            return res.status(404).json({
                success: false,
                message: 'Session not found'
            });
        }

        // Format number
        let formattedNumber = number.replace(/\D/g, '');
        if (!formattedNumber.startsWith('91') && formattedNumber.length === 10) {
            formattedNumber = '91' + formattedNumber;
        }
        const chatId = formattedNumber + '@c.us';

        // Check if number is registered
        const isRegistered = await client.isRegisteredUser(chatId);
        if (!isRegistered) {
            if (file) fs.unlinkSync(file.path);
            return res.status(400).json({
                success: false,
                message: 'Number is not registered on WhatsApp'
            });
        }

        // Get message queue
        const messageQueue = messageQueues.get(fullSessionId);
        if (!messageQueue) {
            if (file) fs.unlinkSync(file.path);
            return res.status(400).json({
                success: false,
                message: 'Message queue not initialized'
            });
        }

        // Add message to queue
        const result = await messageQueue.addMessage({
            sessionId: fullSessionId,
            chatId,
            message,
            file
        });

        res.json({
            success: true,
            message: 'Message queued and sent successfully',
            messageId: result.messageId,
            timestamp: result.timestamp,
            hasFile: result.hasFile,
            delay: user.messageDelay
        });

    } catch (error) {
        console.error('Error sending message:', error);
        if (req.file) fs.unlinkSync(req.file.path);
        res.status(500).json({
            success: false,
            message: 'Failed to send message: ' + error.message
        });
    }
});

// Update message delay
app.post('/api/update-delay', authenticateUser, (req, res) => {
    try {
        const { sessionId, delay } = req.body;
        const user = req.user;

        if (!sessionId || delay === undefined) {
            return res.status(400).json({
                success: false,
                message: 'Session ID and delay are required'
            });
        }

        const fullSessionId = `${user.username}_${sessionId}`;
        const messageQueue = messageQueues.get(fullSessionId);

        if (!messageQueue) {
            return res.status(404).json({
                success: false,
                message: 'Session not found'
            });
        }

        messageQueue.setDelay(parseInt(delay));

        res.json({
            success: true,
            message: 'Message delay updated successfully',
            newDelay: delay
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to update delay'
        });
    }
});

// Destroy session
app.delete('/api/destroy-session/:sessionId', authenticateUser, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const user = req.user;
        const fullSessionId = `${user.username}_${sessionId}`;

        const client = clients.get(fullSessionId);
        if (client) {
            await client.destroy();
            clients.delete(fullSessionId);
        }

        qrCodes.delete(fullSessionId);
        sessionStatus.delete(fullSessionId);
        messageQueues.delete(fullSessionId);

        const infoPath = `./sessions/${fullSessionId}_info.json`;
        if (fs.existsSync(infoPath)) {
            fs.unlinkSync(infoPath);
        }

        res.json({
            success: true,
            message: 'Session destroyed successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error destroying session'
        });
    }
});

// Serve web interface
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html>
<head>
    <title>WhatsApp API with Authentication</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        /* Put your CSS here */
    </style>
</head>
<body>
    <h1>WhatsApp API with Login</h1>
    <div id="app">
        <div id="authSection">
            <h3>User Login</h3>
            <input type="text" id="username" placeholder="Username">
            <input type="password" id="password" placeholder="Password">
            <button onclick="login()">Login</button>
        </div>

        <div id="mainContent" style="display:none;">
            <h3>User Dashboard</h3>
            <p>Welcome, <span id="userDisplayName"></span></p>
            <button onclick="logout()">Logout</button>
        </div>
    </div>

    <script>
        function login() {
            const username = document.getElementById("username").value;
            const password = document.getElementById("password").value;

            if (username === "admin" && password === "admin") {
                localStorage.setItem("user", username);
                document.getElementById("authSection").style.display = "none";
                document.getElementById("mainContent").style.display = "block";
                document.getElementById("userDisplayName").innerText = username;
            } else {
                alert("Invalid credentials");
            }
        }

        function logout() {
            localStorage.removeItem("user");
            document.getElementById("authSection").style.display = "block";
            document.getElementById("mainContent").style.display = "none";
        }

        window.onload = function () {
            const user = localStorage.getItem("user");
            if (user) {
                document.getElementById("authSection").style.display = "none";
                document.getElementById("mainContent").style.display = "block";
                document.getElementById("userDisplayName").innerText = user;
            }
        }
    </script>
</body>
</html>`);
});


app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html'); // Serve clean from file OR
});


// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Enhanced WhatsApp API server running on port ${PORT}`);
    console.log(`Open http://localhost:${PORT} in your browser`);
    console.log(`Admin credentials: ${ADMIN_USERNAME} / ${ADMIN_PASSWORD}`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('Shutting down gracefully...');

    for (const [sessionId, client] of clients) {
        try {
            await client.destroy();
            console.log(`Destroyed session: ${sessionId}`);
        } catch (error) {
            console.error(`Error destroying session ${sessionId}:`, error);
        }
    }

    process.exit(0);
});