#!/bin/bash

# =============================================================================
# RSA Key Pair Generation Script
# Generates RSA-2048 key pair for JWT signing
# =============================================================================

set -e

# Configuration
KEY_DIR="${1:-./keys}"
PRIVATE_KEY="${KEY_DIR}/private.pem"
PUBLIC_KEY="${KEY_DIR}/public.pem"

echo "🔐 RSA Key Pair Generation Script"
echo "================================="

# Create keys directory if it doesn't exist
if [ ! -d "$KEY_DIR" ]; then
    echo "📁 Creating keys directory: $KEY_DIR"
    mkdir -p "$KEY_DIR"
fi

# Check if keys already exist
if [ -f "$PRIVATE_KEY" ] || [ -f "$PUBLIC_KEY" ]; then
    echo "⚠️  Warning: Key files already exist!"
    read -p "Do you want to overwrite them? (y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "❌ Aborted."
        exit 0
    fi
fi

# Generate private key
echo "🔑 Generating RSA-2048 private key..."
openssl genpkey -algorithm RSA -out "$PRIVATE_KEY" -pkeyopt rsa_keygen_bits:2048

# Extract public key
echo "🔑 Extracting public key..."
openssl rsa -pubout -in "$PRIVATE_KEY" -out "$PUBLIC_KEY"

# Set permissions (read-only for owner)
chmod 400 "$PRIVATE_KEY"
chmod 444 "$PUBLIC_KEY"

echo ""
echo "✅ RSA key pair generated successfully!"
echo ""
echo "📄 Private key: $PRIVATE_KEY"
echo "📄 Public key:  $PUBLIC_KEY"
echo ""
echo "⚠️  IMPORTANT SECURITY NOTES:"
echo "   1. NEVER commit the private key to version control!"
echo "   2. Store the private key securely in production."
echo "   3. Use environment variables or secret managers for the key path."
echo ""

# Generate encryption key for AES-256
echo "🔐 Generating AES-256 encryption key..."
ENCRYPTION_KEY=$(openssl rand -base64 32)
echo ""
echo "📋 Add this to your .env file:"
echo "   ENCRYPTION_KEY=$ENCRYPTION_KEY"
echo ""
