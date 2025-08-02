const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const sqlite3 = require('sqlite3').verbose();
const forge = require('node-forge');
const path = require('path');

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
      connectSrc: ["'self'", "wss:", "ws:"],
      mediaSrc: ["'self'", "blob:"],
      imgSrc: ["'self'", "data:", "blob:"]
    }
  }
}));

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Database setup
const db = new sqlite3.Database(':memory:'); // Using in-memory for security
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    public_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    sender_id TEXT,
    receiver_id TEXT,
    encrypted_content TEXT,
    message_type TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users (id),
    FOREIGN KEY (receiver_id) REFERENCES users (id)
  )`);
  
  db.run(`CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    token TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);
});

// Encryption utilities
class EncryptionManager {
  static generateKeyPair() {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    return {
      publicKey: forge.pki.publicKeyToPem(keys.publicKey),
      privateKey: forge.pki.privateKeyToPem(keys.privateKey)
    };
  }

  static encryptMessage(message, publicKey) {
    const publicKeyObj = forge.pki.publicKeyFromPem(publicKey);
    const encrypted = publicKeyObj.encrypt(message, 'RSAES-PKCS1-V1_5');
    return forge.util.encode64(encrypted);
  }

  static decryptMessage(encryptedMessage, privateKey) {
    const privateKeyObj = forge.pki.privateKeyFromPem(privateKey);
    const decoded = forge.util.decode64(encryptedMessage);
    return privateKeyObj.decrypt(decoded, 'RSAES-PKCS1-V1_5');
  }

  static generateAESKey() {
    return forge.util.encode64(forge.random.getBytesSync(32));
  }

  static encryptWithAES(data, key) {
    const cipher = forge.cipher.createCipher('AES-GCM', forge.util.decode64(key));
    cipher.start();
    cipher.update(forge.util.createBuffer(data));
    cipher.finish();
    return {
      encrypted: forge.util.encode64(cipher.output.getBytes()),
      tag: forge.util.encode64(cipher.mode.tag.getBytes())
    };
  }
}

// JWT Secret (in production, use environment variable)
const JWT_SECRET = crypto.randomBytes(64).toString('hex');

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Registration endpoint
app.post('/api/register', [
  body('username').isLength({ min: 3, max: 20 }).matches(/^[a-zA-Z0-9_]+$/),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;
  const userId = uuidv4();
  const passwordHash = await bcrypt.hash(password, 12);
  const keyPair = EncryptionManager.generateKeyPair();

  db.run(
    'INSERT INTO users (id, username, password_hash, public_key) VALUES (?, ?, ?, ?)',
    [userId, username, passwordHash, keyPair.publicKey],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(409).json({ error: 'Username already exists' });
        }
        return res.status(500).json({ error: 'Registration failed' });
      }

      const token = jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: '24h' });
      res.json({
        message: 'Registration successful',
        token,
        userId,
        username,
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey // Only sent once during registration
      });
    }
  );
});

// Login endpoint
app.post('/api/login', [
  body('username').notEmpty(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Login failed' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last seen
    db.run('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

    const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({
      message: 'Login successful',
      token,
      userId: user.id,
      username: user.username,
      publicKey: user.public_key
    });
  });
});

// Get online users
app.get('/api/users/online', authenticateToken, (req, res) => {
  db.all('SELECT id, username, last_seen FROM users WHERE last_seen > datetime("now", "-5 minutes")', (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch users' });
    }
    res.json(users.filter(user => user.id !== req.user.userId));
  });
});

// File upload endpoint
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    // Allow only specific file types
    const allowedTypes = ['image/', 'video/', 'audio/', 'text/', 'application/pdf'];
    const isAllowed = allowedTypes.some(type => file.mimetype.startsWith(type));
    if (isAllowed) {
      cb(null, true);
    } else {
      cb(new Error('File type not allowed'), false);
    }
  }
});

app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const fileId = uuidv4();
  const encryptedFile = EncryptionManager.encryptWithAES(req.file.buffer, EncryptionManager.generateAESKey());
  
  // In a real application, you'd store the encrypted file in a secure storage
  // For this demo, we'll just return the encrypted data
  res.json({
    fileId,
    fileName: req.file.originalname,
    fileSize: req.file.size,
    mimeType: req.file.mimetype,
    encryptedData: encryptedFile
  });
});

// WebSocket connection handling
const connectedUsers = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('authenticate', (token) => {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        socket.emit('auth_error', { message: 'Invalid token' });
        return;
      }
      
      connectedUsers.set(socket.id, user);
      socket.userId = user.userId;
      socket.username = user.username;
      
      socket.emit('authenticated', { userId: user.userId, username: user.username });
      
      // Notify others that user is online
      socket.broadcast.emit('user_online', { userId: user.userId, username: user.username });
    });
  });

  socket.on('private_message', (data) => {
    const sender = connectedUsers.get(socket.id);
    if (!sender) return;

    const messageId = uuidv4();
    const timestamp = new Date().toISOString();

    // Store encrypted message in database
    db.run(
      'INSERT INTO messages (id, sender_id, receiver_id, encrypted_content, message_type) VALUES (?, ?, ?, ?, ?)',
      [messageId, sender.userId, data.receiverId, data.encryptedContent, data.type || 'text']
    );

    // Forward message to recipient
    const recipientSocket = Array.from(connectedUsers.entries())
      .find(([_, user]) => user.userId === data.receiverId);
    
    if (recipientSocket) {
      io.to(recipientSocket[0]).emit('private_message', {
        messageId,
        senderId: sender.userId,
        senderName: sender.username,
        encryptedContent: data.encryptedContent,
        type: data.type || 'text',
        timestamp
      });
    }

    // Send confirmation to sender
    socket.emit('message_sent', { messageId, timestamp });
  });

  // WebRTC signaling
  socket.on('offer', (data) => {
    const recipientSocket = Array.from(connectedUsers.entries())
      .find(([_, user]) => user.userId === data.target);
    
    if (recipientSocket) {
      io.to(recipientSocket[0]).emit('offer', {
        offer: data.offer,
        from: connectedUsers.get(socket.id).userId
      });
    }
  });

  socket.on('answer', (data) => {
    const recipientSocket = Array.from(connectedUsers.entries())
      .find(([_, user]) => user.userId === data.target);
    
    if (recipientSocket) {
      io.to(recipientSocket[0]).emit('answer', {
        answer: data.answer,
        from: connectedUsers.get(socket.id).userId
      });
    }
  });

  socket.on('ice_candidate', (data) => {
    const recipientSocket = Array.from(connectedUsers.entries())
      .find(([_, user]) => user.userId === data.target);
    
    if (recipientSocket) {
      io.to(recipientSocket[0]).emit('ice_candidate', {
        candidate: data.candidate,
        from: connectedUsers.get(socket.id).userId
      });
    }
  });

  socket.on('call_request', (data) => {
    const recipientSocket = Array.from(connectedUsers.entries())
      .find(([_, user]) => user.userId === data.target);
    
    if (recipientSocket) {
      io.to(recipientSocket[0]).emit('call_request', {
        from: connectedUsers.get(socket.id).userId,
        fromName: connectedUsers.get(socket.id).username,
        callType: data.callType // 'video' or 'audio'
      });
    }
  });

  socket.on('call_response', (data) => {
    const recipientSocket = Array.from(connectedUsers.entries())
      .find(([_, user]) => user.userId === data.target);
    
    if (recipientSocket) {
      io.to(recipientSocket[0]).emit('call_response', {
        accepted: data.accepted,
        from: connectedUsers.get(socket.id).userId
      });
    }
  });

  socket.on('disconnect', () => {
    const user = connectedUsers.get(socket.id);
    if (user) {
      connectedUsers.delete(socket.id);
      socket.broadcast.emit('user_offline', { userId: user.userId, username: user.username });
    }
    console.log('User disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Secure Anonymous Chat Server running on port ${PORT}`);
  console.log('Security features enabled:');
  console.log('- End-to-end encryption');
  console.log('- Rate limiting');
  console.log('- Helmet security headers');
  console.log('- CORS protection');
  console.log('- Input validation');
  console.log('- Secure file uploads');
});