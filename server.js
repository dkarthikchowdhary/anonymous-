const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "blob:"],
            mediaSrc: ["'self'", "blob:"],
            connectSrc: ["'self'", "ws:", "wss:"]
        }
    }
}));

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP'
});
app.use(limiter);

// Static files
app.use(express.static('public'));

// In-memory storage (for demo - use secure database in production)
let users = new Map();
let activeUsers = new Map();
let chatRooms = new Map();
let messages = new Map();

// JWT secret (use environment variable in production)
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// Encryption functions
function encrypt(text) {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(JWT_SECRET, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(algorithm, key);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return {
        encrypted,
        iv: iv.toString('hex')
    };
}

function decrypt(encryptedData) {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(JWT_SECRET, 'salt', 32);
    const decipher = crypto.createDecipher(algorithm, key);
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
}

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = uuidv4() + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB limit
    },
    fileFilter: (req, file, cb) => {
        // Allow most file types but exclude dangerous ones
        const dangerousTypes = ['.exe', '.bat', '.cmd', '.scr', '.pif'];
        const ext = path.extname(file.originalname).toLowerCase();
        
        if (dangerousTypes.includes(ext)) {
            return cb(new Error('File type not allowed'), false);
        }
        cb(null, true);
    }
});

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.sendStatus(401);
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Routes
app.post('/api/signup', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        // Check if user exists
        if (users.has(username)) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Generate anonymous ID
        const anonymousId = crypto.randomBytes(16).toString('hex');
        
        // Create user
        const user = {
            id: uuidv4(),
            username,
            email: email || null,
            password: hashedPassword,
            anonymousId,
            createdAt: new Date(),
            isOnline: false,
            lastSeen: new Date()
        };

        users.set(username, user);
        
        // Generate token
        const token = jwt.sign(
            { userId: user.id, username: user.username, anonymousId: user.anonymousId },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'User created successfully',
            token,
            user: {
                id: user.id,
                username: user.username,
                anonymousId: user.anonymousId
            }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        const user = users.get(username);
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Update last seen
        user.lastSeen = new Date();
        user.isOnline = true;

        // Generate token
        const token = jwt.sign(
            { userId: user.id, username: user.username, anonymousId: user.anonymousId },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                anonymousId: user.anonymousId
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/users', authenticateToken, (req, res) => {
    const userList = Array.from(users.values()).map(user => ({
        id: user.id,
        username: user.username,
        anonymousId: user.anonymousId,
        isOnline: user.isOnline,
        lastSeen: user.lastSeen
    }));
    
    res.json(userList);
});

app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        res.json({
            message: 'File uploaded successfully',
            file: {
                filename: req.file.filename,
                originalname: req.file.originalname,
                size: req.file.size,
                mimetype: req.file.mimetype,
                url: `/uploads/${req.file.filename}`
            }
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Upload failed' });
    }
});

app.use('/uploads', express.static('uploads'));

// Socket.IO for real-time communication
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    
    if (!token) {
        return next(new Error('Authentication error'));
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return next(new Error('Authentication error'));
        }
        socket.userId = decoded.userId;
        socket.username = decoded.username;
        socket.anonymousId = decoded.anonymousId;
        next();
    });
});

io.on('connection', (socket) => {
    console.log(`User ${socket.username} connected`);
    
    // Add user to active users
    activeUsers.set(socket.userId, {
        socketId: socket.id,
        username: socket.username,
        anonymousId: socket.anonymousId,
        isOnline: true
    });

    // Update user status
    if (users.has(socket.username)) {
        users.get(socket.username).isOnline = true;
    }

    // Broadcast user list update
    io.emit('userListUpdate', Array.from(activeUsers.values()));

    // Handle private messages
    socket.on('privateMessage', (data) => {
        const { recipientId, message, messageType = 'text' } = data;
        
        // Encrypt message
        const encryptedMessage = encrypt(message);
        
        const messageObj = {
            id: uuidv4(),
            senderId: socket.userId,
            senderUsername: socket.username,
            senderAnonymousId: socket.anonymousId,
            recipientId,
            message: encryptedMessage,
            messageType,
            timestamp: new Date()
        };

        // Store message
        const conversationId = [socket.userId, recipientId].sort().join('-');
        if (!messages.has(conversationId)) {
            messages.set(conversationId, []);
        }
        messages.get(conversationId).push(messageObj);

        // Send to recipient if online
        const recipient = activeUsers.get(recipientId);
        if (recipient) {
            io.to(recipient.socketId).emit('newMessage', {
                ...messageObj,
                message: decrypt(encryptedMessage) // Decrypt for recipient
            });
        }

        // Send confirmation to sender
        socket.emit('messageSent', {
            ...messageObj,
            message: decrypt(encryptedMessage)
        });
    });

    // Handle video call initiation
    socket.on('initiateCall', (data) => {
        const { recipientId, callType } = data; // callType: 'video' or 'audio'
        const recipient = activeUsers.get(recipientId);
        
        if (recipient) {
            io.to(recipient.socketId).emit('incomingCall', {
                callerId: socket.userId,
                callerUsername: socket.username,
                callerAnonymousId: socket.anonymousId,
                callType
            });
        }
    });

    // Handle call responses
    socket.on('callResponse', (data) => {
        const { callerId, accepted } = data;
        const caller = activeUsers.get(callerId);
        
        if (caller) {
            io.to(caller.socketId).emit('callResponse', {
                accepted,
                recipientId: socket.userId,
                recipientUsername: socket.username
            });
        }
    });

    // Handle WebRTC signaling
    socket.on('offer', (data) => {
        const { recipientId, offer } = data;
        const recipient = activeUsers.get(recipientId);
        
        if (recipient) {
            io.to(recipient.socketId).emit('offer', {
                senderId: socket.userId,
                offer
            });
        }
    });

    socket.on('answer', (data) => {
        const { recipientId, answer } = data;
        const recipient = activeUsers.get(recipientId);
        
        if (recipient) {
            io.to(recipient.socketId).emit('answer', {
                senderId: socket.userId,
                answer
            });
        }
    });

    socket.on('iceCandidate', (data) => {
        const { recipientId, candidate } = data;
        const recipient = activeUsers.get(recipientId);
        
        if (recipient) {
            io.to(recipient.socketId).emit('iceCandidate', {
                senderId: socket.userId,
                candidate
            });
        }
    });

    // Handle disconnection
    socket.on('disconnect', () => {
        console.log(`User ${socket.username} disconnected`);
        
        // Remove from active users
        activeUsers.delete(socket.userId);
        
        // Update user status
        if (users.has(socket.username)) {
            const user = users.get(socket.username);
            user.isOnline = false;
            user.lastSeen = new Date();
        }

        // Broadcast user list update
        io.emit('userListUpdate', Array.from(activeUsers.values()));
    });
});

// Error handling
app.use((error, req, res, next) => {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Secure Anonymous Chat Server running on port ${PORT}`);
    console.log(`Visit http://localhost:${PORT} to access the application`);
});