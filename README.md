# SecureChat - Anonymous Secure Messaging Platform

A secure, anonymous chatting website with end-to-end encryption, video/audio calls, and file sharing - designed with privacy and security similar to Tor browser principles.

## 🔒 Security Features

- **End-to-End Encryption**: All messages are encrypted before transmission
- **Anonymous User IDs**: Users can chat without revealing personal information
- **No-Logs Policy**: Messages are not permanently stored on the server
- **Secure Authentication**: Password hashing with bcrypt and JWT tokens
- **Rate Limiting**: Protection against spam and abuse
- **Content Security Policy**: XSS protection and secure content loading
- **File Upload Security**: Dangerous file types are blocked

## 🚀 Features

### Core Functionality
- ✅ **Secure Authentication** (Signup/Login)
- ✅ **Real-time Messaging** with Socket.IO
- ✅ **Video Calls** using WebRTC
- ✅ **Audio Calls** using WebRTC
- ✅ **File Sharing** with encryption
- ✅ **Anonymous Profiles** with user IDs
- ✅ **Online/Offline Status**
- ✅ **Modern UI** with dark theme

### Security & Privacy
- ✅ **Message Encryption** (AES-256-GCM)
- ✅ **Anonymous User System**
- ✅ **Secure Headers** (Helmet.js)
- ✅ **Rate Limiting**
- ✅ **Input Sanitization**
- ✅ **CSRF Protection**

## 📋 Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Modern web browser with WebRTC support

## 🛠️ Installation

1. **Clone or download the project files**
2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the server:**
   ```bash
   npm start
   ```
   
   For development with auto-restart:
   ```bash
   npm run dev
   ```

4. **Access the application:**
   Open your browser and navigate to `http://localhost:3000`

## 📖 Usage

### Getting Started

1. **Create Account**: Click "Create Anonymous Account" and provide a username and password
2. **Login**: Use your credentials to securely log in
3. **Select User**: Choose a user from the sidebar to start chatting
4. **Send Messages**: Type in the message box and press Enter or click send
5. **Make Calls**: Use the video/audio call buttons in the chat header
6. **Share Files**: Click the file attachment button to share files securely

### Chat Interface

- **Left Sidebar**: Shows online users and their status
- **Chat Header**: Displays selected user info and call/file sharing options
- **Message Area**: Shows encrypted conversation history
- **Message Input**: Type and send secure messages

### Video/Audio Calls

- Click the 📹 (video) or 📞 (audio) button to initiate a call
- Accept or decline incoming calls using the modal interface
- Use call controls to mute/unmute, toggle video, or end the call

### File Sharing

- Click the 📎 button to select and share files
- Files are uploaded securely and shared through encrypted messages
- File types are validated for security

## 🔧 Configuration

### Environment Variables

Create a `.env` file for production configuration:

```env
NODE_ENV=production
PORT=3000
JWT_SECRET=your-super-secure-jwt-secret-key
```

### Security Settings

The application includes several security measures:

- **JWT Secret**: Automatically generated or set via environment variable
- **Rate Limiting**: 100 requests per 15-minute window per IP
- **File Upload Limits**: 100MB maximum file size
- **Content Security Policy**: Restricts resource loading for security

## 🏗️ Project Structure

```
secure-anonymous-chat/
├── server.js              # Main server file with Express and Socket.IO
├── package.json           # Dependencies and scripts
├── README.md              # This file
├── public/                # Static frontend files
│   ├── index.html         # Main HTML file
│   ├── styles.css         # CSS styling
│   └── app.js             # Frontend JavaScript
└── uploads/               # File upload directory (created automatically)
```

## 🔒 Security Implementation

### Message Encryption
- Uses AES-256-GCM encryption for all messages
- Each message is encrypted before transmission
- Decryption happens on the client side

### User Authentication
- Passwords are hashed using bcrypt with salt rounds of 12
- JWT tokens for session management
- Anonymous user IDs for privacy

### Network Security
- Helmet.js for security headers
- CORS protection
- Rate limiting to prevent abuse
- Input validation and sanitization

## 🌐 Browser Compatibility

- Chrome/Chromium 60+
- Firefox 55+
- Safari 11+
- Edge 79+

WebRTC support is required for video/audio calling features.

## 🚨 Important Security Notes

### For Production Use:

1. **Set a strong JWT secret** in environment variables
2. **Use HTTPS** in production (required for WebRTC)
3. **Configure proper firewall rules**
4. **Use a production database** instead of in-memory storage
5. **Set up proper monitoring and logging**
6. **Regular security updates** for dependencies

### Privacy Considerations:

- Messages are encrypted in transit and at rest in memory
- No persistent message storage by default
- Anonymous user system protects identity
- IP addresses may still be logged by the server/proxy

## 🔧 Development

### Running in Development Mode

```bash
npm run dev
```

This starts the server with nodemon for automatic restarts on file changes.

### Building for Production

```bash
npm run build
```

### Testing

The application includes basic error handling and validation. For production use, consider adding:

- Unit tests for encryption/decryption functions
- Integration tests for API endpoints
- End-to-end tests for chat functionality

## 🤝 Contributing

This is a demonstration project showing secure chat implementation. For production use, additional security auditing and testing is recommended.

## ⚠️ Disclaimer

This application is designed for educational and demonstration purposes. While it implements strong security measures, any production deployment should undergo thorough security testing and auditing.

## 📄 License

MIT License - See LICENSE file for details

---

**Built with security and privacy in mind** 🔒

For questions or issues, please refer to the code comments or create an issue in the project repository.
