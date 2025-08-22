#!/bin/bash

# Setup environment variables for the application
echo "Setting up environment variables..."

if [ -f .env ]; then
    echo "Warning: .env file already exists. This will overwrite it."
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 1
    fi
fi

# Copy example file to .env
cp env.example .env

echo "Environment file created from env.example"
echo "Please edit .env file with your actual values before running docker-compose"
echo ""
echo "Required changes:"
echo "1. Set a secure POSTGRES_PASSWORD"
echo "2. Update SECRET_KEY with a secure random string"
echo "3. Set your actual email in CERTBOT_EMAIL"
echo "4. Set your domain in CERTBOT_DOMAIN"
echo ""
echo "You can generate a secure SECRET_KEY using:"
echo "python3 -c 'import secrets; print(secrets.token_urlsafe(32))'"
