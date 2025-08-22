#!/bin/bash

DOMAIN="hadal.data-line.gr"

echo "=== DNS Troubleshooting for $DOMAIN ==="
echo

echo "1. Checking if domain resolves:"
if nslookup $DOMAIN > /dev/null 2>&1; then
    echo "✓ Domain resolves"
    nslookup $DOMAIN
else
    echo "✗ Domain does not resolve"
    echo "Please check your DNS configuration"
fi
echo

echo "2. Checking A records:"
dig +short A $DOMAIN
echo

echo "3. Checking AAAA records:"
dig +short AAAA $DOMAIN
echo

echo "4. Checking from different DNS servers:"
echo "Google DNS (8.8.8.8):"
dig @8.8.8.8 +short A $DOMAIN
echo "Cloudflare DNS (1.1.1.1):"
dig @1.1.1.1 +short A $DOMAIN
echo

echo "5. Checking your server's public IP:"
PUBLIC_IP=$(curl -s ifconfig.me)
echo "Your server's public IP: $PUBLIC_IP"
echo

echo "6. Testing HTTP connectivity:"
if curl -s -o /dev/null -w "%{http_code}" http://$DOMAIN; then
    echo "✓ HTTP is accessible"
else
    echo "✗ HTTP is not accessible"
fi
echo

echo "7. Testing port 80 accessibility:"
if nc -z $DOMAIN 80 2>/dev/null; then
    echo "✓ Port 80 is open"
else
    echo "✗ Port 80 is closed or blocked"
fi
echo

echo "=== Recommendations ==="
echo "1. Ensure your DNS A record points $DOMAIN to your server's IP: $PUBLIC_IP"
echo "2. Wait for DNS propagation (can take up to 48 hours)"
echo "3. Ensure port 80 is open on your server"
echo "4. Test with: curl -I http://$DOMAIN"
