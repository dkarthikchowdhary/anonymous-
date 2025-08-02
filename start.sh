#!/bin/bash

echo "🔒 SecureChat - Anonymous Secure Messaging Platform"
echo "=================================================="
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js version 14 or higher."
    echo "   Download from: https://nodejs.org/"
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 14 ]; then
    echo "❌ Node.js version $NODE_VERSION is too old. Please install version 14 or higher."
    exit 1
fi

echo "✅ Node.js $(node -v) detected"
echo ""

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install npm."
    exit 1
fi

echo "✅ npm $(npm -v) detected"
echo ""

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
    echo ""
fi

# Check if installation was successful
if [ ! -d "node_modules" ]; then
    echo "❌ Failed to install dependencies. Please run 'npm install' manually."
    exit 1
fi

echo "🚀 Starting SecureChat server..."
echo ""
echo "🌐 The application will be available at: http://localhost:3000"
echo "🔒 All communications are encrypted end-to-end"
echo "🕶️  Anonymous messaging with secure user IDs"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start the server
npm start