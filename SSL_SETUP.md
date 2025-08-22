# Let's Encrypt SSL Setup Guide

This guide will help you set up Let's Encrypt SSL certificates for your Nginx server running in Docker.

## Prerequisites

1. A domain name pointing to your server's IP address
2. Ports 80 and 443 open on your server
3. Docker and Docker Compose installed

## Configuration Steps

### 1. Update Domain Configuration

Before running the setup, you need to update the following files with your actual domain:

**In `docker-compose.yml`:**
- Replace `your-email@example.com` with your actual email address
- Replace `your-domain.com` with your actual domain name

**In `nginx.conf`:**
- Replace `your-domain.com` with your actual domain name

**In `init-letsencrypt.sh`:**
- Replace `your-domain.com` with your actual domain name
- Replace `your-email@example.com` with your actual email address

### 2. Create Required Directories

```bash
mkdir -p certbot/conf certbot/www
```

### 3. Make Scripts Executable

```bash
chmod +x init-letsencrypt.sh renew-ssl.sh
```

### 4. Initialize SSL Certificates

```bash
./init-letsencrypt.sh
```

This script will:
- Create dummy certificates to start Nginx
- Request real certificates from Let's Encrypt
- Configure Nginx to use the new certificates

### 5. Start Your Services

```bash
docker-compose up -d
```

## Certificate Renewal

Let's Encrypt certificates expire after 90 days. To set up automatic renewal:

### Option 1: Manual Renewal
Run the renewal script manually:
```bash
./renew-ssl.sh
```

### Option 2: Automatic Renewal with Cron
Add a cron job to automatically renew certificates:

```bash
# Edit crontab
crontab -e

# Add this line to run renewal twice daily
0 12,0 * * * /path/to/your/project/renew-ssl.sh >> /var/log/cert-renew.log 2>&1
```

## Testing Your Setup

1. **Check Certificate Status:**
   ```bash
   docker-compose exec nginx nginx -t
   ```

2. **Test SSL Configuration:**
   Visit https://your-domain.com and verify:
   - The lock icon appears in your browser
   - No SSL warnings are shown
   - HTTP requests redirect to HTTPS

3. **Check Certificate Details:**
   ```bash
   docker-compose exec certbot certbot certificates
   ```

## Troubleshooting

### Common Issues

1. **Domain Not Resolving:**
   - Ensure your domain points to the correct IP address
   - Check DNS propagation with `nslookup your-domain.com`

2. **Port 80/443 Blocked:**
   - Verify firewall settings allow traffic on ports 80 and 443
   - Check if other services are using these ports

3. **Certificate Request Fails:**
   - Ensure the domain is accessible from the internet
   - Check that the `.well-known/acme-challenge/` path is accessible
   - Verify Nginx is running and serving the challenge files

4. **Nginx Configuration Errors:**
   - Check Nginx logs: `docker-compose logs nginx`
   - Test configuration: `docker-compose exec nginx nginx -t`

### Logs and Debugging

```bash
# View Nginx logs
docker-compose logs nginx

# View Certbot logs
docker-compose logs certbot

# Check certificate status
docker-compose exec certbot certbot certificates

# Test Nginx configuration
docker-compose exec nginx nginx -t
```

## Security Considerations

1. **Keep Certificates Updated:** Let's Encrypt certificates expire after 90 days
2. **Monitor Renewals:** Set up monitoring for certificate renewal failures
3. **Backup Certificates:** Consider backing up your certificate files
4. **Security Headers:** The Nginx configuration includes security headers for enhanced protection

## File Structure

```
your-project/
├── docker-compose.yml          # Updated with SSL support
├── nginx.conf                  # Updated with SSL configuration
├── init-letsencrypt.sh         # Initial certificate setup script
├── renew-ssl.sh               # Certificate renewal script
├── certbot/
│   ├── conf/                  # Certificate configuration files
│   └── www/                   # Webroot for ACME challenges
└── SSL_SETUP.md              # This guide
```

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review Docker and Nginx logs
3. Verify your domain configuration
4. Ensure all prerequisites are met
