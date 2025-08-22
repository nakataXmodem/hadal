#!/bin/bash

# Configuration
domains=(hadal.data-line.gr)
rsa_key_size=4096
data_path="./certbot"
email="nakatamodem@i2pmail.org" # Adding a valid address is strongly recommended
staging=1 # Set to 1 if you're testing your setup to avoid hitting request limits

echo "=== Let's Encrypt SSL Certificate Setup ==="
echo "Domain: ${domains[0]}"
echo "Email: $email"
echo "Staging mode: $staging"
echo

# Check if domain resolves
echo "### Checking DNS resolution for ${domains[0]} ..."
if ! nslookup ${domains[0]} > /dev/null 2>&1; then
    echo "ERROR: Domain ${domains[0]} does not resolve to an IP address."
    echo "Please ensure:"
    echo "1. The domain name is correct"
    echo "2. DNS records are properly configured"
    echo "3. DNS propagation has completed (can take up to 48 hours)"
    echo
    echo "You can test DNS resolution with: nslookup ${domains[0]}"
    exit 1
fi

# Get the IP address the domain resolves to
domain_ip=$(nslookup ${domains[0]} | grep -A1 "Name:" | tail -1 | awk '{print $2}')
echo "Domain ${domains[0]} resolves to: $domain_ip"

# Check if this IP matches your server's public IP
echo "Please verify that $domain_ip is your server's public IP address."
echo "If not, update your DNS records to point ${domains[0]} to your server's IP."
echo

if [ -d "$data_path" ]; then
  read -p "Existing data found for $domains. Continue and replace existing certificate? (y/N) " decision
  if [ "$decision" != "Y" ] && [ "$decision" != "y" ]; then
    exit
  fi
fi

if [ ! -e "$data_path/conf/options-ssl-nginx.conf" ] || [ ! -e "$data_path/conf/ssl-dhparams.pem" ]; then
  echo "### Downloading recommended TLS parameters ..."
  mkdir -p "$data_path/conf"
  curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf > "$data_path/conf/options-ssl-nginx.conf"
  curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem > "$data_path/conf/ssl-dhparams.pem"
  echo
fi

echo "### Creating dummy certificate for $domains ..."
path="/etc/letsencrypt/live/$domains"
mkdir -p "$data_path/conf/live/$domains"
docker-compose run --rm --entrypoint "\
  openssl req -x509 -nodes -newkey rsa:$rsa_key_size -days 1\
    -keyout '$path/privkey.pem' \
    -out '$path/fullchain.pem' \
    -subj '/CN=localhost'" certbot
echo

echo "### Starting nginx with temporary configuration ..."
# Use temporary configuration for initial setup
cp nginx.conf nginx.conf.backup
cp nginx.conf.temp nginx.conf
docker-compose up --force-recreate -d nginx
echo

echo "### Waiting for nginx to start ..."
sleep 10

echo "### Testing nginx configuration ..."
if ! docker-compose exec nginx nginx -t; then
    echo "ERROR: Nginx configuration test failed"
    docker-compose logs nginx
    exit 1
fi

echo "### Testing domain accessibility ..."
if ! curl -s -o /dev/null -w "%{http_code}" http://${domains[0]} | grep -q "200\|404\|502"; then
    echo "WARNING: Domain ${domains[0]} might not be accessible from the internet"
    echo "This could be due to:"
    echo "1. Firewall blocking port 80"
    echo "2. DNS not fully propagated"
    echo "3. Server not accessible from the internet"
    echo
    read -p "Continue anyway? (y/N) " decision
    if [ "$decision" != "Y" ] && [ "$decision" != "y" ]; then
        exit 1
    fi
fi

echo "### Deleting dummy certificate for $domains ..."
docker-compose run --rm --entrypoint "\
  rm -Rf /etc/letsencrypt/live/$domains && \
  rm -Rf /etc/letsencrypt/archive/$domains && \
  rm -Rf /etc/letsencrypt/renewal/$domains.conf" certbot
echo

echo "### Requesting Let's Encrypt certificate for $domains ..."
#Join $domains to -d args
domain_args=""
for domain in "${domains[@]}"; do
  domain_args="$domain_args -d $domain"
done

# Select appropriate email arg
case "$email" in
  "") email_arg="--register-unsafely-without-email" ;;
  *) email_arg="--email $email" ;;
esac

# Enable staging mode if needed
if [ $staging != "0" ]; then staging_arg="--staging"; fi

docker-compose run --rm --entrypoint "\
  certbot certonly --webroot -w /var/www/certbot \
    $staging_arg \
    $email_arg \
    $domain_args \
    --rsa-key-size $rsa_key_size \
    --agree-tos \
    --force-renewal" certbot

if [ $? -eq 0 ]; then
    echo "### Certificate obtained successfully!"
    echo "### Switching to full SSL configuration ..."
    cp nginx.conf.backup nginx.conf
    docker-compose exec nginx nginx -s reload
    echo "### SSL setup completed successfully!"
    echo "### Your site should now be accessible at https://${domains[0]}"
else
    echo "### Certificate request failed!"
    echo "### Common issues:"
    echo "1. DNS not properly configured"
    echo "2. Domain not accessible from the internet"
    echo "3. Firewall blocking port 80"
    echo "4. Let's Encrypt rate limits (if staging=0)"
    echo
    echo "### Keeping temporary configuration for debugging"
    echo "### Check logs with: docker-compose logs certbot"
    echo "### Test domain accessibility: curl -I http://${domains[0]}"
fi
