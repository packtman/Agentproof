#!/bin/bash
# Deploy AgentProof to a DigitalOcean Droplet
# 
# Prerequisites:
# 1. Create a Droplet (Ubuntu 22.04, Basic, $6/month)
# 2. SSH into it: ssh root@YOUR_DROPLET_IP
# 3. Run this script

set -e

echo "🪪 Installing AgentProof on DigitalOcean..."

# Update system
apt update && apt upgrade -y

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs

# Install build tools for native modules (better-sqlite3)
apt install -y build-essential python3

# Install PM2 for process management
npm install -g pm2

# Install Caddy for reverse proxy + auto HTTPS
apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update
apt install -y caddy

# Create app directory
mkdir -p /opt/agentproof
cd /opt/agentproof

# Clone the repo (or copy files)
echo "📥 Clone your repo or copy files to /opt/agentproof"
echo "   git clone https://github.com/YOUR_USERNAME/agentproof.git ."
echo ""
echo "Then run these commands:"
echo ""
cat << 'EOF'
# Install dependencies
cd /opt/agentproof
npm install

# Build the app
npm run build

# Initialize database
npm run db:setup

# Generate JWT keys
node -e "
const crypto = require('crypto');
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
console.log('JWT_PRIVATE_KEY=' + privateKey.export({type:'pkcs8',format:'pem'}).toString('base64').replace(/\n/g,''));
console.log('JWT_PUBLIC_KEY=' + publicKey.export({type:'spki',format:'pem'}).toString('base64').replace(/\n/g,''));
"

# Create .env file
cat > .env << ENVEOF
PORT=3000
NODE_ENV=production
DATABASE_PATH=/opt/agentproof/data/agentproof.db
JWT_PRIVATE_KEY=<paste from above>
JWT_PUBLIC_KEY=<paste from above>
ENVEOF

# Start with PM2
pm2 start dist/index.js --name agentproof
pm2 save
pm2 startup

# Configure Caddy for your domain
# Edit /etc/caddy/Caddyfile:
cat > /etc/caddy/Caddyfile << CADDYEOF
agentdmv.com {
    reverse_proxy localhost:3000
}
CADDYEOF

# Reload Caddy
systemctl reload caddy

echo "✅ AgentProof is running at https://agentdmv.com"
EOF
