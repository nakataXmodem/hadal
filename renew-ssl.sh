#!/bin/bash

# Script to renew Let's Encrypt certificates
echo "### Renewing Let's Encrypt certificates ..."

# Renew certificates
docker-compose run --rm certbot renew

# Reload nginx to use the renewed certificates
docker-compose exec nginx nginx -s reload

echo "### Certificate renewal completed!"
