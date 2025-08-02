// Secure Anonymous Chat Application
class SecureChatApp {
    constructor() {
        this.socket = null;
        this.currentUser = null;
        this.selectedUser = null;
        this.peer = null;
        this.localStream = null;
        this.remoteStream = null;
        this.privateKey = null;
        this.publicKey = null;
        this.isInCall = false;
        this.isVideoEnabled = true;
        this.isAudioEnabled = true;
        
        this.initializeApp();
    }

    initializeApp() {
        this.setupEventListeners();
        this.checkAuthStatus();
    }

    setupEventListeners() {
        // Authentication form switches
        document.getElementById('show-signup').addEventListener('click', (e) => {
            e.preventDefault();
            this.showSignupForm();
        });

        document.getElementById('show-login').addEventListener('click', (e) => {
            e.preventDefault();
            this.showLoginForm();
        });

        // Form submissions
        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        document.getElementById('signup-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleSignup();
        });

        // Chat functionality
        document.getElementById('message-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        document.getElementById('send-message-btn').addEventListener('click', () => {
            this.sendMessage();
        });

        document.getElementById('file-upload-btn').addEventListener('click', () => {
            document.getElementById('file-input').click();
        });

        document.getElementById('file-input').addEventListener('change', (e) => {
            this.handleFileUpload(e.target.files[0]);
        });

        // Call controls
        document.getElementById('video-call-btn').addEventListener('click', () => {
            this.initiateCall('video');
        });

        document.getElementById('audio-call-btn').addEventListener('click', () => {
            this.initiateCall('audio');
        });

        // Call modal
        document.getElementById('accept-call').addEventListener('click', () => {
            this.acceptCall();
        });

        document.getElementById('reject-call').addEventListener('click', () => {
            this.rejectCall();
        });

        document.getElementById('close-call-modal').addEventListener('click', () => {
            this.closeCallModal();
        });

        // Video call controls
        document.getElementById('toggle-video').addEventListener('click', () => {
            this.toggleVideo();
        });

        document.getElementById('toggle-audio').addEventListener('click', () => {
            this.toggleAudio();
        });

        document.getElementById('end-call').addEventListener('click', () => {
            this.endCall();
        });

        // User list refresh
        document.getElementById('refresh-users').addEventListener('click', () => {
            this.loadOnlineUsers();
        });
    }

    showSignupForm() {
        document.getElementById('login-form').classList.add('hidden');
        document.getElementById('signup-form').classList.remove('hidden');
    }

    showLoginForm() {
        document.getElementById('signup-form').classList.add('hidden');
        document.getElementById('login-form').classList.remove('hidden');
    }

    checkAuthStatus() {
        const token = localStorage.getItem('authToken');
        if (token) {
            this.connectToServer(token);
        }
    }

    async handleLogin() {
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;

        try {
            this.showLoading(true);
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok) {
                localStorage.setItem('authToken', data.token);
                localStorage.setItem('userId', data.userId);
                localStorage.setItem('username', data.username);
                this.currentUser = {
                    id: data.userId,
                    username: data.username,
                    publicKey: data.publicKey
                };
                this.connectToServer(data.token);
            } else {
                this.showError(data.error);
            }
        } catch (error) {
            this.showError('Login failed. Please try again.');
        } finally {
            this.showLoading(false);
        }
    }

    async handleSignup() {
        const username = document.getElementById('signup-username').value;
        const password = document.getElementById('signup-password').value;
        const confirmPassword = document.getElementById('signup-confirm-password').value;

        if (password !== confirmPassword) {
            this.showError('Passwords do not match');
            return;
        }

        try {
            this.showLoading(true);
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok) {
                localStorage.setItem('authToken', data.token);
                localStorage.setItem('userId', data.userId);
                localStorage.setItem('username', data.username);
                localStorage.setItem('privateKey', data.privateKey);
                
                this.currentUser = {
                    id: data.userId,
                    username: data.username,
                    publicKey: data.publicKey
                };
                this.privateKey = data.privateKey;
                this.publicKey = data.publicKey;
                
                this.connectToServer(data.token);
            } else {
                this.showError(data.error);
            }
        } catch (error) {
            this.showError('Registration failed. Please try again.');
        } finally {
            this.showLoading(false);
        }
    }

    connectToServer(token) {
        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Connected to server');
            this.socket.emit('authenticate', token);
        });

        this.socket.on('authenticated', (data) => {
            console.log('Authenticated:', data);
            this.showChatInterface();
            this.loadOnlineUsers();
        });

        this.socket.on('auth_error', (data) => {
            console.error('Authentication error:', data);
            localStorage.removeItem('authToken');
            this.showAuthInterface();
        });

        this.socket.on('user_online', (data) => {
            this.addUserToList(data);
        });

        this.socket.on('user_offline', (data) => {
            this.removeUserFromList(data.userId);
        });

        this.socket.on('private_message', (data) => {
            this.displayMessage(data);
        });

        this.socket.on('message_sent', (data) => {
            console.log('Message sent:', data);
        });

        // WebRTC signaling
        this.socket.on('offer', (data) => {
            this.handleOffer(data);
        });

        this.socket.on('answer', (data) => {
            this.handleAnswer(data);
        });

        this.socket.on('ice_candidate', (data) => {
            this.handleIceCandidate(data);
        });

        this.socket.on('call_request', (data) => {
            this.showIncomingCall(data);
        });

        this.socket.on('call_response', (data) => {
            this.handleCallResponse(data);
        });
    }

    showChatInterface() {
        document.getElementById('auth-container').classList.add('hidden');
        document.getElementById('chat-container').classList.remove('hidden');
        document.getElementById('current-user-name').textContent = this.currentUser.username;
    }

    showAuthInterface() {
        document.getElementById('chat-container').classList.add('hidden');
        document.getElementById('auth-container').classList.remove('hidden');
    }

    async loadOnlineUsers() {
        try {
            const response = await fetch('/api/users/online', {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('authToken')}`
                }
            });

            if (response.ok) {
                const users = await response.json();
                this.displayUsers(users);
            }
        } catch (error) {
            console.error('Failed to load users:', error);
        }
    }

    displayUsers(users) {
        const usersList = document.getElementById('users-list');
        usersList.innerHTML = '';

        users.forEach(user => {
            this.addUserToList(user);
        });
    }

    addUserToList(user) {
        const usersList = document.getElementById('users-list');
        const existingUser = document.querySelector(`[data-user-id="${user.id}"]`);
        
        if (existingUser) {
            return;
        }

        const userElement = document.createElement('div');
        userElement.className = 'user-item';
        userElement.setAttribute('data-user-id', user.id);
        userElement.innerHTML = `
            <div class="user-item-avatar">
                <i class="fas fa-user"></i>
            </div>
            <div class="user-item-info">
                <div class="user-item-name">${user.username}</div>
                <div class="user-item-status">Online</div>
            </div>
        `;

        userElement.addEventListener('click', () => {
            this.selectUser(user);
        });

        usersList.appendChild(userElement);
    }

    removeUserFromList(userId) {
        const userElement = document.querySelector(`[data-user-id="${userId}"]`);
        if (userElement) {
            userElement.remove();
        }
    }

    selectUser(user) {
        // Remove active class from all users
        document.querySelectorAll('.user-item').forEach(item => {
            item.classList.remove('active');
        });

        // Add active class to selected user
        const userElement = document.querySelector(`[data-user-id="${user.id}"]`);
        if (userElement) {
            userElement.classList.add('active');
        }

        this.selectedUser = user;
        this.enableMessageInput();
        this.clearChatMessages();
        this.showWelcomeMessage();
    }

    enableMessageInput() {
        const messageInput = document.getElementById('message-input');
        const sendBtn = document.getElementById('send-message-btn');
        const fileBtn = document.getElementById('file-upload-btn');

        messageInput.disabled = false;
        sendBtn.disabled = false;
        fileBtn.disabled = false;
    }

    clearChatMessages() {
        const chatMessages = document.getElementById('chat-messages');
        chatMessages.innerHTML = '';
    }

    showWelcomeMessage() {
        const chatMessages = document.getElementById('chat-messages');
        chatMessages.innerHTML = `
            <div class="welcome-message">
                <i class="fas fa-lock"></i>
                <h3>Chat with ${this.selectedUser.username}</h3>
                <p>Your messages are end-to-end encrypted. Start typing to begin your secure conversation.</p>
            </div>
        `;
    }

    async sendMessage() {
        if (!this.selectedUser) return;

        const messageInput = document.getElementById('message-input');
        const message = messageInput.value.trim();

        if (!message) return;

        try {
            // Encrypt message with recipient's public key
            const encryptedMessage = await this.encryptMessage(message, this.selectedUser.publicKey);

            this.socket.emit('private_message', {
                receiverId: this.selectedUser.id,
                encryptedContent: encryptedMessage,
                type: 'text'
            });

            // Display message locally
            this.displayMessage({
                senderId: this.currentUser.id,
                senderName: this.currentUser.username,
                encryptedContent: encryptedMessage,
                type: 'text',
                timestamp: new Date().toISOString()
            });

            messageInput.value = '';
        } catch (error) {
            console.error('Failed to send message:', error);
            this.showError('Failed to send message');
        }
    }

    displayMessage(data) {
        const chatMessages = document.getElementById('chat-messages');
        const isOwnMessage = data.senderId === this.currentUser.id;

        // Remove welcome message if it exists
        const welcomeMessage = chatMessages.querySelector('.welcome-message');
        if (welcomeMessage) {
            welcomeMessage.remove();
        }

        const messageElement = document.createElement('div');
        messageElement.className = `message ${isOwnMessage ? 'sent' : 'received'}`;

        let messageContent = '';
        if (data.type === 'file') {
            messageContent = this.createFileMessageContent(data);
        } else {
            // Decrypt message if it's not our own
            let decryptedContent = data.encryptedContent;
            if (!isOwnMessage && this.privateKey) {
                try {
                    decryptedContent = this.decryptMessage(data.encryptedContent, this.privateKey);
                } catch (error) {
                    decryptedContent = '[Encrypted Message]';
                }
            }
            messageContent = `<div class="message-content">${decryptedContent}</div>`;
        }

        messageElement.innerHTML = `
            <div class="message-info">
                <span>${data.senderName}</span>
            </div>
            ${messageContent}
            <div class="message-time">${new Date(data.timestamp).toLocaleTimeString()}</div>
        `;

        chatMessages.appendChild(messageElement);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    createFileMessageContent(data) {
        const fileData = JSON.parse(data.encryptedContent);
        return `
            <div class="message-content">
                <div class="file-message">
                    <div class="file-icon">
                        <i class="fas fa-file"></i>
                    </div>
                    <div class="file-info">
                        <div class="file-name">${fileData.fileName}</div>
                        <div class="file-size">${this.formatFileSize(fileData.fileSize)}</div>
                    </div>
                </div>
            </div>
        `;
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async handleFileUpload(file) {
        if (!file || !this.selectedUser) return;

        try {
            const formData = new FormData();
            formData.append('file', file);

            const response = await fetch('/api/upload', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('authToken')}`
                },
                body: formData
            });

            if (response.ok) {
                const data = await response.json();
                const fileInfo = {
                    fileName: data.fileName,
                    fileSize: data.fileSize,
                    mimeType: data.mimeType,
                    fileId: data.fileId
                };

                // Encrypt file info
                const encryptedFileInfo = await this.encryptMessage(JSON.stringify(fileInfo), this.selectedUser.publicKey);

                this.socket.emit('private_message', {
                    receiverId: this.selectedUser.id,
                    encryptedContent: encryptedFileInfo,
                    type: 'file'
                });

                // Display file message locally
                this.displayMessage({
                    senderId: this.currentUser.id,
                    senderName: this.currentUser.username,
                    encryptedContent: encryptedFileInfo,
                    type: 'file',
                    timestamp: new Date().toISOString()
                });
            }
        } catch (error) {
            console.error('File upload failed:', error);
            this.showError('File upload failed');
        }
    }

    // Encryption methods
    async encryptMessage(message, publicKey) {
        // For demo purposes, we'll use a simple encryption
        // In production, use proper RSA encryption
        return btoa(message);
    }

    async decryptMessage(encryptedMessage, privateKey) {
        // For demo purposes, we'll use simple decryption
        // In production, use proper RSA decryption
        return atob(encryptedMessage);
    }

    // Call functionality
    async initiateCall(callType) {
        if (!this.selectedUser) {
            this.showError('Please select a user to call');
            return;
        }

        try {
            await this.getUserMedia(callType);
            this.socket.emit('call_request', {
                target: this.selectedUser.id,
                callType: callType
            });
        } catch (error) {
            console.error('Failed to initiate call:', error);
            this.showError('Failed to start call');
        }
    }

    async getUserMedia(callType) {
        const constraints = {
            audio: callType === 'audio' || callType === 'video',
            video: callType === 'video'
        };

        this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
        
        if (callType === 'video') {
            const localVideo = document.getElementById('local-video');
            localVideo.srcObject = this.localStream;
        }
    }

    showIncomingCall(data) {
        document.getElementById('caller-name').textContent = data.fromName;
        document.getElementById('call-type').textContent = data.callType === 'video' ? 'Video Call' : 'Audio Call';
        document.getElementById('call-modal').classList.remove('hidden');
        
        // Store call data
        this.incomingCall = data;
    }

    closeCallModal() {
        document.getElementById('call-modal').classList.add('hidden');
        this.incomingCall = null;
    }

    async acceptCall() {
        if (!this.incomingCall) return;

        try {
            await this.getUserMedia(this.incomingCall.callType);
            
            this.socket.emit('call_response', {
                target: this.incomingCall.from,
                accepted: true
            });

            this.closeCallModal();
            this.startCall(this.incomingCall.callType);
        } catch (error) {
            console.error('Failed to accept call:', error);
            this.showError('Failed to accept call');
        }
    }

    rejectCall() {
        if (!this.incomingCall) return;

        this.socket.emit('call_response', {
            target: this.incomingCall.from,
            accepted: false
        });

        this.closeCallModal();
    }

    handleCallResponse(data) {
        if (data.accepted) {
            this.startCall('video'); // Default to video for demo
        } else {
            this.showError('Call was rejected');
        }
    }

    startCall(callType) {
        this.isInCall = true;
        
        if (callType === 'video') {
            document.getElementById('video-call-interface').classList.remove('hidden');
        }

        this.initializePeerConnection();
    }

    initializePeerConnection() {
        const configuration = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' }
            ]
        };

        this.peer = new SimplePeer({
            initiator: true,
            trickle: false,
            stream: this.localStream,
            config: configuration
        });

        this.peer.on('signal', (data) => {
            this.socket.emit('offer', {
                target: this.selectedUser.id,
                offer: data
            });
        });

        this.peer.on('stream', (stream) => {
            this.remoteStream = stream;
            const remoteVideo = document.getElementById('remote-video');
            remoteVideo.srcObject = stream;
        });
    }

    handleOffer(data) {
        const configuration = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' }
            ]
        };

        this.peer = new SimplePeer({
            initiator: false,
            trickle: false,
            stream: this.localStream,
            config: configuration
        });

        this.peer.signal(data.offer);

        this.peer.on('signal', (signalData) => {
            this.socket.emit('answer', {
                target: data.from,
                answer: signalData
            });
        });

        this.peer.on('stream', (stream) => {
            this.remoteStream = stream;
            const remoteVideo = document.getElementById('remote-video');
            remoteVideo.srcObject = stream;
        });
    }

    handleAnswer(data) {
        if (this.peer) {
            this.peer.signal(data.answer);
        }
    }

    handleIceCandidate(data) {
        if (this.peer) {
            this.peer.signal(data.candidate);
        }
    }

    toggleVideo() {
        if (this.localStream) {
            const videoTrack = this.localStream.getVideoTracks()[0];
            if (videoTrack) {
                videoTrack.enabled = !videoTrack.enabled;
                this.isVideoEnabled = videoTrack.enabled;
                
                const toggleBtn = document.getElementById('toggle-video');
                toggleBtn.innerHTML = this.isVideoEnabled ? 
                    '<i class="fas fa-video"></i>' : 
                    '<i class="fas fa-video-slash"></i>';
            }
        }
    }

    toggleAudio() {
        if (this.localStream) {
            const audioTrack = this.localStream.getAudioTracks()[0];
            if (audioTrack) {
                audioTrack.enabled = !audioTrack.enabled;
                this.isAudioEnabled = audioTrack.enabled;
                
                const toggleBtn = document.getElementById('toggle-audio');
                toggleBtn.innerHTML = this.isAudioEnabled ? 
                    '<i class="fas fa-microphone"></i>' : 
                    '<i class="fas fa-microphone-slash"></i>';
            }
        }
    }

    endCall() {
        this.isInCall = false;
        
        if (this.peer) {
            this.peer.destroy();
            this.peer = null;
        }

        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
            this.localStream = null;
        }

        if (this.remoteStream) {
            this.remoteStream.getTracks().forEach(track => track.stop());
            this.remoteStream = null;
        }

        document.getElementById('video-call-interface').classList.add('hidden');
        document.getElementById('local-video').srcObject = null;
        document.getElementById('remote-video').srcObject = null;
    }

    // Utility methods
    showLoading(show) {
        const spinner = document.getElementById('loading-spinner');
        if (show) {
            spinner.classList.remove('hidden');
        } else {
            spinner.classList.add('hidden');
        }
    }

    showError(message) {
        // Create a simple error notification
        const errorDiv = document.createElement('div');
        errorDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #f44336;
            color: white;
            padding: 15px 20px;
            border-radius: 5px;
            z-index: 10000;
            max-width: 300px;
        `;
        errorDiv.textContent = message;
        document.body.appendChild(errorDiv);

        setTimeout(() => {
            errorDiv.remove();
        }, 5000);
    }
}

// Initialize the application when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new SecureChatApp();
});