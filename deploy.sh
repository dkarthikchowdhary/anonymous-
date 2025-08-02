#!/bin/bash

# Secure Anonymous Chat - Deployment Script
# This script sets up and deploys the secure chat application

echo "🔒 Secure Anonymous Chat - Deployment Script"
echo "=============================================="

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js v14 or higher."
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 14 ]; then
    echo "❌ Node.js version 14 or higher is required. Current version: $(node -v)"
    exit 1
fi

echo "✅ Node.js version: $(node -v)"

# Install dependencies
echo "📦 Installing dependencies..."
npm install

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo "✅ Dependencies installed successfully"

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "🔧 Creating .env file..."
    cat > .env << EOF
PORT=3000
JWT_SECRET=$(openssl rand -hex 64)
NODE_ENV=production
EOF
    echo "✅ .env file created with secure JWT secret"
else
    echo "✅ .env file already exists"
fi

# Run security tests
echo "🧪 Running security tests..."
node test.js

if [ $? -ne 0 ]; then
    echo "❌ Security tests failed"
    exit 1
fi

echo "✅ Security tests passed"

# Start the server
echo "🚀 Starting Secure Anonymous Chat server..."
echo "📱 Access the application at: http://localhost:3000"
echo "🔒 Security features enabled:"
echo "   - End-to-end encryption"
echo "   - Rate limiting"
echo "   - Helmet security headers"
echo "   - CORS protection"
echo "   - Input validation"
echo "   - Secure file uploads"
echo ""
echo "Press Ctrl+C to stop the server"

npm start