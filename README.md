# Secure Anonymous Chat Application

A highly secure, anonymous chatting platform with end-to-end encryption, video/audio calls, and file sharing capabilities. Built with security features similar to Tor browser for maximum privacy protection.

## 🔒 Security Features

- **End-to-End Encryption**: All messages are encrypted using RSA-2048 encryption
- **Anonymous Communication**: No personal information required for registration
- **Secure File Sharing**: Encrypted file uploads with type validation
- **WebRTC Video/Audio Calls**: Peer-to-peer communication with STUN servers
- **Rate Limiting**: Protection against brute force attacks
- **Input Validation**: Comprehensive validation for all user inputs
- **CORS Protection**: Cross-origin request protection
- **Helmet Security Headers**: Advanced security headers implementation
- **In-Memory Database**: No persistent data storage for enhanced privacy
- **JWT Authentication**: Secure token-based authentication

## 🚀 Features

### Core Functionality
- **User Registration/Login**: Secure authentication system
- **Real-time Messaging**: Instant encrypted message delivery
- **Video Calls**: High-quality peer-to-peer video communication
- **Audio Calls**: Crystal clear voice communication
- **File Sharing**: Secure file upload and sharing (images, videos, audio, documents)
- **Online User List**: Real-time online user detection
- **Message History**: Encrypted message storage and retrieval

### User Interface
- **Modern Dark Theme**: Beautiful, responsive design
- **Mobile Responsive**: Works perfectly on all devices
- **Real-time Updates**: Live user status and message delivery
- **Call Controls**: Video/audio toggle, mute, and call management
- **File Upload Interface**: Drag-and-drop file sharing
- **Loading States**: Smooth user experience with loading indicators

## 🛠️ Technology Stack

### Backend
- **Node.js**: Server runtime environment
- **Express.js**: Web application framework
- **Socket.IO**: Real-time bidirectional communication
- **SQLite3**: In-memory database for security
- **bcryptjs**: Password hashing
- **jsonwebtoken**: JWT authentication
- **node-forge**: Cryptographic operations
- **multer**: File upload handling
- **helmet**: Security headers
- **cors**: Cross-origin resource sharing
- **express-rate-limit**: Rate limiting protection

### Frontend
- **Vanilla JavaScript**: No framework dependencies
- **WebRTC**: Peer-to-peer communication
- **SimplePeer**: WebRTC abstraction library
- **Font Awesome**: Icon library
- **CSS3**: Modern styling with animations

## 📦 Installation

### Prerequisites
- Node.js (v14 or higher)
- npm or yarn package manager

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd secure-anonymous-chat
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the development server**
   ```bash
   npm run dev
   ```

4. **Access the application**
   Open your browser and navigate to `http://localhost:3000`

### Production Deployment

1. **Build the application**
   ```bash
   npm run build
   ```

2. **Start the production server**
   ```bash
   npm start
   ```

## 🔧 Configuration

### Environment Variables
Create a `.env` file in the root directory:

```env
PORT=3000
JWT_SECRET=your-super-secret-jwt-key
NODE_ENV=production
```

### Security Settings
The application includes several security configurations:

- **Rate Limiting**: 100 requests per 15 minutes per IP
- **File Upload Limits**: 10MB maximum file size
- **Allowed File Types**: Images, videos, audio, text, PDFs
- **Password Requirements**: Minimum 8 characters
- **Username Requirements**: 3-20 characters, alphanumeric and underscore only

## 🎯 Usage Guide

### Registration
1. Click "Sign up" on the login page
2. Enter a username (3-20 characters)
3. Create a strong password (minimum 8 characters)
4. Confirm your password
5. Click "Sign Up"

### Login
1. Enter your username and password
2. Click "Login"
3. You'll be automatically connected to the chat interface

### Sending Messages
1. Select a user from the online users list
2. Type your message in the input field
3. Press Enter or click the send button
4. Messages are automatically encrypted and sent

### Making Calls
1. Select a user from the online users list
2. Click the video call (📹) or audio call (📞) button
3. Allow camera/microphone permissions when prompted
4. Wait for the other user to accept the call

### File Sharing
1. Select a user from the online users list
2. Click the paperclip icon (📎)
3. Choose a file to upload
4. The file will be encrypted and sent securely

## 🔐 Security Architecture

### Encryption Flow
1. **Key Generation**: RSA-2048 key pairs generated during registration
2. **Message Encryption**: Messages encrypted with recipient's public key
3. **File Encryption**: Files encrypted with AES-256-GCM
4. **Secure Transmission**: All data transmitted over encrypted WebSocket connections

### Privacy Protection
- **No Data Persistence**: Messages stored in memory only
- **Anonymous Users**: No personal information required
- **End-to-End Encryption**: Only sender and recipient can decrypt messages
- **No Message Logging**: Server doesn't store message content
- **Automatic Cleanup**: Data automatically cleared on server restart

### Network Security
- **WebRTC STUN Servers**: Google's public STUN servers for NAT traversal
- **Secure WebSocket**: All real-time communication encrypted
- **CORS Protection**: Prevents unauthorized cross-origin requests
- **Rate Limiting**: Prevents abuse and DDoS attacks

## 🧪 Testing

Run the test suite:
```bash
npm test
```

## 📱 Browser Compatibility

- Chrome 60+
- Firefox 55+
- Safari 12+
- Edge 79+

## 🚨 Security Considerations

### For Production Use
1. **Use HTTPS**: Always deploy with SSL/TLS encryption
2. **Strong JWT Secret**: Use a cryptographically secure random string
3. **Database Security**: Consider using a more robust database with encryption
4. **File Storage**: Implement secure cloud storage for files
5. **Monitoring**: Add logging and monitoring for security events
6. **Backup Strategy**: Implement secure backup procedures

### Privacy Best Practices
1. **Regular Key Rotation**: Implement automatic key rotation
2. **Session Management**: Implement proper session timeout
3. **Audit Logging**: Log security events without compromising privacy
4. **Incident Response**: Have a plan for security incidents

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This application is designed for educational and demonstration purposes. For production use in high-security environments, additional security measures and professional security audits are recommended.

## 🆘 Support

For support and questions:
- Create an issue in the GitHub repository
- Check the documentation
- Review the security considerations

## 🔄 Updates

Stay updated with the latest security patches and features by regularly checking for updates and following security best practices.

---

**Built with ❤️ for secure communication**
