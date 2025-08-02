class SecureChatApp {
    constructor() {
        this.socket = null;
        this.currentUser = null;
        this.token = null;
        this.selectedUser = null;
        this.messages = new Map();
        this.activeCall = null;
        this.localStream = null;
        this.remoteStream = null;
        this.peerConnection = null;
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.checkAuthentication();
        
        // Hide loading screen after a short delay
        setTimeout(() => {
            document.getElementById('loadingScreen').style.display = 'none';
        }, 1500);
    }

    setupEventListeners() {
        // Auth form switching
        document.getElementById('showSignup').addEventListener('click', (e) => {
            e.preventDefault();
            this.showSignupForm();
        });

        document.getElementById('showLogin').addEventListener('click', (e) => {
            e.preventDefault();
            this.showLoginForm();
        });

        // Form submissions
        document.getElementById('loginFormElement').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        document.getElementById('signupFormElement').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleSignup();
        });

        // Chat functionality
        document.getElementById('sendBtn').addEventListener('click', () => {
            this.sendMessage();
        });

        document.getElementById('messageInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendMessage();
            }
        });

        // Call functionality
        document.getElementById('audioCallBtn').addEventListener('click', () => {
            this.initiateCall('audio');
        });

        document.getElementById('videoCallBtn').addEventListener('click', () => {
            this.initiateCall('video');
        });

        // File sharing
        document.getElementById('fileShareBtn').addEventListener('click', () => {
            document.getElementById('fileInput').click();
        });

        document.getElementById('fileInput').addEventListener('change', (e) => {
            this.handleFileShare(e.target.files);
        });

        // Call controls
        document.getElementById('acceptCallBtn').addEventListener('click', () => {
            this.acceptCall();
        });

        document.getElementById('declineCallBtn').addEventListener('click', () => {
            this.declineCall();
        });

        document.getElementById('endCallBtn').addEventListener('click', () => {
            this.endCall();
        });

        document.getElementById('muteBtn').addEventListener('click', () => {
            this.toggleMute();
        });

        document.getElementById('videoToggleBtn').addEventListener('click', () => {
            this.toggleVideo();
        });

        // Logout
        document.getElementById('logoutBtn').addEventListener('click', () => {
            this.logout();
        });

        // Refresh users
        document.getElementById('refreshUsers').addEventListener('click', () => {
            this.loadUsers();
        });
    }

    showSignupForm() {
        document.getElementById('loginForm').classList.remove('active');
        document.getElementById('signupForm').classList.add('active');
    }

    showLoginForm() {
        document.getElementById('signupForm').classList.remove('active');
        document.getElementById('loginForm').classList.add('active');
    }

    async handleLogin() {
        const username = document.getElementById('loginUsername').value;
        const password = document.getElementById('loginPassword').value;

        if (!username || !password) {
            this.showNotification('Please fill in all fields', 'error');
            return;
        }

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok) {
                this.token = data.token;
                this.currentUser = data.user;
                localStorage.setItem('token', this.token);
                localStorage.setItem('user', JSON.stringify(this.currentUser));
                
                this.showNotification('Login successful! Welcome to SecureChat', 'success');
                this.showChatSection();
                this.connectSocket();
            } else {
                this.showNotification(data.error || 'Login failed', 'error');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showNotification('Network error. Please try again.', 'error');
        }
    }

    async handleSignup() {
        const username = document.getElementById('signupUsername').value;
        const password = document.getElementById('signupPassword').value;
        const email = document.getElementById('signupEmail').value;

        if (!username || !password) {
            this.showNotification('Username and password are required', 'error');
            return;
        }

        if (password.length < 6) {
            this.showNotification('Password must be at least 6 characters', 'error');
            return;
        }

        try {
            const response = await fetch('/api/signup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password, email })
            });

            const data = await response.json();

            if (response.ok) {
                this.token = data.token;
                this.currentUser = data.user;
                localStorage.setItem('token', this.token);
                localStorage.setItem('user', JSON.stringify(this.currentUser));
                
                this.showNotification('Account created successfully! Welcome to SecureChat', 'success');
                this.showChatSection();
                this.connectSocket();
            } else {
                this.showNotification(data.error || 'Signup failed', 'error');
            }
        } catch (error) {
            console.error('Signup error:', error);
            this.showNotification('Network error. Please try again.', 'error');
        }
    }

    checkAuthentication() {
        const token = localStorage.getItem('token');
        const user = localStorage.getItem('user');

        if (token && user) {
            this.token = token;
            this.currentUser = JSON.parse(user);
            this.showChatSection();
            this.connectSocket();
        } else {
            this.showAuthSection();
        }
    }

    showAuthSection() {
        document.getElementById('authSection').classList.remove('hidden');
        document.getElementById('chatSection').classList.add('hidden');
    }

    showChatSection() {
        document.getElementById('authSection').classList.add('hidden');
        document.getElementById('chatSection').classList.remove('hidden');
        
        // Update user info in header
        document.getElementById('currentUsername').textContent = this.currentUser.username;
        document.getElementById('userInitial').textContent = this.currentUser.username.charAt(0).toUpperCase();
        
        this.loadUsers();
    }

    connectSocket() {
        this.socket = io({
            auth: {
                token: this.token
            }
        });

        this.socket.on('connect', () => {
            console.log('Connected to secure server');
            this.showNotification('Connected to secure server', 'success');
        });

        this.socket.on('disconnect', () => {
            console.log('Disconnected from server');
            this.showNotification('Connection lost. Attempting to reconnect...', 'error');
        });

        this.socket.on('userListUpdate', (users) => {
            this.updateUsersList(users);
        });

        this.socket.on('newMessage', (message) => {
            this.handleNewMessage(message);
        });

        this.socket.on('messageSent', (message) => {
            this.handleMessageSent(message);
        });

        this.socket.on('incomingCall', (callData) => {
            this.handleIncomingCall(callData);
        });

        this.socket.on('callResponse', (response) => {
            this.handleCallResponse(response);
        });

        this.socket.on('offer', (data) => {
            this.handleOffer(data);
        });

        this.socket.on('answer', (data) => {
            this.handleAnswer(data);
        });

        this.socket.on('iceCandidate', (data) => {
            this.handleIceCandidate(data);
        });
    }

    async loadUsers() {
        try {
            const response = await fetch('/api/users', {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (response.ok) {
                const users = await response.json();
                this.updateUsersList(users.filter(user => user.id !== this.currentUser.id));
            }
        } catch (error) {
            console.error('Error loading users:', error);
        }
    }

    updateUsersList(users) {
        const usersList = document.getElementById('usersList');
        usersList.innerHTML = '';

        users.forEach(user => {
            const userElement = document.createElement('div');
            userElement.className = 'user-item';
            userElement.dataset.userId = user.id;
            
            userElement.innerHTML = `
                <div class="user-item-avatar">
                    <span>${user.username.charAt(0).toUpperCase()}</span>
                </div>
                <div class="user-item-info">
                    <div class="user-item-name">${user.username}</div>
                    <div class="user-item-status ${user.isOnline ? 'online' : 'offline'}">
                        ${user.isOnline ? 'Online' : 'Offline'}
                    </div>
                </div>
            `;

            userElement.addEventListener('click', () => {
                this.selectUser(user);
            });

            usersList.appendChild(userElement);
        });
    }

    selectUser(user) {
        this.selectedUser = user;
        
        // Update UI
        document.querySelectorAll('.user-item').forEach(item => {
            item.classList.remove('active');
        });
        
        document.querySelector(`[data-user-id="${user.id}"]`).classList.add('active');
        
        // Show chat window
        document.getElementById('welcomeScreen').classList.add('hidden');
        document.getElementById('chatWindow').classList.remove('hidden');
        
        // Update chat header
        document.getElementById('chatUsername').textContent = user.username;
        document.getElementById('chatUserInitial').textContent = user.username.charAt(0).toUpperCase();
        document.getElementById('chatUserStatus').textContent = user.isOnline ? 'Online' : 'Offline';
        document.getElementById('chatUserStatus').className = `status ${user.isOnline ? 'online' : 'offline'}`;
        
        // Load messages for this conversation
        this.loadMessages(user.id);
    }

    loadMessages(userId) {
        const messagesContainer = document.getElementById('messagesContainer');
        messagesContainer.innerHTML = '';
        
        const conversationId = [this.currentUser.id, userId].sort().join('-');
        const messages = this.messages.get(conversationId) || [];
        
        messages.forEach(message => {
            this.displayMessage(message);
        });
        
        // Scroll to bottom
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    sendMessage() {
        const messageInput = document.getElementById('messageInput');
        const message = messageInput.value.trim();
        
        if (!message || !this.selectedUser) return;
        
        this.socket.emit('privateMessage', {
            recipientId: this.selectedUser.id,
            message: message,
            messageType: 'text'
        });
        
        messageInput.value = '';
    }

    handleNewMessage(message) {
        // Store message
        const conversationId = [message.senderId, message.recipientId].sort().join('-');
        if (!this.messages.has(conversationId)) {
            this.messages.set(conversationId, []);
        }
        this.messages.get(conversationId).push(message);
        
        // Display message if it's for the current conversation
        if (this.selectedUser && 
            (message.senderId === this.selectedUser.id || message.recipientId === this.selectedUser.id)) {
            this.displayMessage(message);
        }
        
        // Show notification if not in current conversation
        if (!this.selectedUser || message.senderId !== this.selectedUser.id) {
            this.showNotification(`New message from ${message.senderUsername}`, 'success');
        }
    }

    handleMessageSent(message) {
        // Store message
        const conversationId = [message.senderId, message.recipientId].sort().join('-');
        if (!this.messages.has(conversationId)) {
            this.messages.set(conversationId, []);
        }
        this.messages.get(conversationId).push(message);
        
        // Display message if it's for the current conversation
        if (this.selectedUser && message.recipientId === this.selectedUser.id) {
            this.displayMessage(message);
        }
    }

    displayMessage(message) {
        const messagesContainer = document.getElementById('messagesContainer');
        
        const messageElement = document.createElement('div');
        messageElement.className = `message ${message.senderId === this.currentUser.id ? 'sent' : 'received'}`;
        
        const timestamp = new Date(message.timestamp).toLocaleTimeString();
        
        messageElement.innerHTML = `
            <div class="message-info">
                ${message.senderId === this.currentUser.id ? 'You' : message.senderUsername}
            </div>
            <div class="message-content">${this.escapeHtml(message.message)}</div>
            <div class="message-time">${timestamp}</div>
        `;
        
        messagesContainer.appendChild(messageElement);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    async handleFileShare(files) {
        if (!files.length || !this.selectedUser) return;
        
        for (const file of files) {
            const formData = new FormData();
            formData.append('file', file);
            
            try {
                const response = await fetch('/api/upload', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    },
                    body: formData
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    // Send file message
                    this.socket.emit('privateMessage', {
                        recipientId: this.selectedUser.id,
                        message: `📁 File: ${data.file.originalname} (${this.formatFileSize(data.file.size)})`,
                        messageType: 'file',
                        fileData: data.file
                    });
                    
                    this.showNotification('File shared successfully', 'success');
                } else {
                    this.showNotification('File upload failed', 'error');
                }
            } catch (error) {
                console.error('File upload error:', error);
                this.showNotification('File upload failed', 'error');
            }
        }
    }

    initiateCall(callType) {
        if (!this.selectedUser) {
            this.showNotification('Please select a user to call', 'error');
            return;
        }
        
        this.socket.emit('initiateCall', {
            recipientId: this.selectedUser.id,
            callType: callType
        });
        
        this.showNotification(`Initiating ${callType} call...`, 'success');
    }

    handleIncomingCall(callData) {
        const modal = document.getElementById('incomingCallModal');
        document.getElementById('callerName').textContent = callData.callerUsername;
        document.getElementById('callerInitial').textContent = callData.callerUsername.charAt(0).toUpperCase();
        document.getElementById('callTypeText').textContent = `${callData.callType.charAt(0).toUpperCase() + callData.callType.slice(1)} Call`;
        
        this.incomingCallData = callData;
        modal.classList.remove('hidden');
    }

    acceptCall() {
        document.getElementById('incomingCallModal').classList.add('hidden');
        
        this.socket.emit('callResponse', {
            callerId: this.incomingCallData.callerId,
            accepted: true
        });
        
        this.startCall(this.incomingCallData.callType, false);
    }

    declineCall() {
        document.getElementById('incomingCallModal').classList.add('hidden');
        
        this.socket.emit('callResponse', {
            callerId: this.incomingCallData.callerId,
            accepted: false
        });
    }

    handleCallResponse(response) {
        if (response.accepted) {
            this.showNotification('Call accepted!', 'success');
            this.startCall('video', true); // Assume video for now
        } else {
            this.showNotification('Call declined', 'error');
        }
    }

    async startCall(callType, isInitiator) {
        try {
            // Get user media
            this.localStream = await navigator.mediaDevices.getUserMedia({
                video: callType === 'video',
                audio: true
            });
            
            // Setup peer connection
            this.peerConnection = new RTCPeerConnection({
                iceServers: [
                    { urls: 'stun:stun.l.google.com:19302' }
                ]
            });
            
            // Add local stream
            this.localStream.getTracks().forEach(track => {
                this.peerConnection.addTrack(track, this.localStream);
            });
            
            // Handle remote stream
            this.peerConnection.ontrack = (event) => {
                this.remoteStream = event.streams[0];
                document.getElementById('remoteVideo').srcObject = this.remoteStream;
            };
            
            // Handle ICE candidates
            this.peerConnection.onicecandidate = (event) => {
                if (event.candidate) {
                    this.socket.emit('iceCandidate', {
                        recipientId: this.selectedUser.id,
                        candidate: event.candidate
                    });
                }
            };
            
            // Show video call modal
            document.getElementById('localVideo').srcObject = this.localStream;
            document.getElementById('videoCallModal').classList.remove('hidden');
            
            if (isInitiator) {
                // Create offer
                const offer = await this.peerConnection.createOffer();
                await this.peerConnection.setLocalDescription(offer);
                
                this.socket.emit('offer', {
                    recipientId: this.selectedUser.id,
                    offer: offer
                });
            }
            
        } catch (error) {
            console.error('Error starting call:', error);
            this.showNotification('Failed to start call', 'error');
        }
    }

    async handleOffer(data) {
        try {
            await this.peerConnection.setRemoteDescription(data.offer);
            
            const answer = await this.peerConnection.createAnswer();
            await this.peerConnection.setLocalDescription(answer);
            
            this.socket.emit('answer', {
                recipientId: data.senderId,
                answer: answer
            });
        } catch (error) {
            console.error('Error handling offer:', error);
        }
    }

    async handleAnswer(data) {
        try {
            await this.peerConnection.setRemoteDescription(data.answer);
        } catch (error) {
            console.error('Error handling answer:', error);
        }
    }

    async handleIceCandidate(data) {
        try {
            await this.peerConnection.addIceCandidate(data.candidate);
        } catch (error) {
            console.error('Error handling ICE candidate:', error);
        }
    }

    endCall() {
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
        }
        
        if (this.peerConnection) {
            this.peerConnection.close();
        }
        
        document.getElementById('videoCallModal').classList.add('hidden');
        this.localStream = null;
        this.remoteStream = null;
        this.peerConnection = null;
    }

    toggleMute() {
        if (this.localStream) {
            const audioTrack = this.localStream.getAudioTracks()[0];
            audioTrack.enabled = !audioTrack.enabled;
            
            const muteBtn = document.getElementById('muteBtn');
            muteBtn.textContent = audioTrack.enabled ? '🎤' : '🔇';
        }
    }

    toggleVideo() {
        if (this.localStream) {
            const videoTrack = this.localStream.getVideoTracks()[0];
            if (videoTrack) {
                videoTrack.enabled = !videoTrack.enabled;
                
                const videoBtn = document.getElementById('videoToggleBtn');
                videoBtn.textContent = videoTrack.enabled ? '📹' : '📷';
            }
        }
    }

    logout() {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        
        if (this.socket) {
            this.socket.disconnect();
        }
        
        this.token = null;
        this.currentUser = null;
        this.selectedUser = null;
        this.messages.clear();
        
        this.showAuthSection();
        this.showNotification('Logged out successfully', 'success');
    }

    showNotification(message, type = 'info') {
        const container = document.getElementById('notificationContainer');
        
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        container.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }

    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}

// Initialize the app when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new SecureChatApp();
});