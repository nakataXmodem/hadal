# Hadal - Network Scanner & Response Analyzer

A comprehensive network scanning and response analysis platform built with Python, featuring a web interface for viewing scan results and a distributed crawler for network reconnaissance.

## 🚀 Features

- **Network Block Management**: Claim and manage network blocks for scanning
- **Distributed Crawling**: Asynchronous crawler for scanning IP addresses on ports 80/443
- **Advanced Search**: Real-time search with filtering across all response fields
- **Web Interface**: Modern web UI for viewing and analyzing scan results
- **API Endpoints**: RESTful API for integration with other tools
- **Telegram Notifications**: Real-time notifications for application events
- **Docker Support**: Complete containerized deployment
- **Database Migrations**: Alembic-based database schema management

## 🏗️ Architecture

- **Backend**: Starlette (ASGI) web framework
- **Database**: PostgreSQL with async SQLAlchemy
- **Frontend**: Jinja2 templates with modern JavaScript
- **Crawler**: AsyncIO-based network scanner
- **Deployment**: Docker Compose with Nginx reverse proxy

## 📋 Prerequisites

- Python 3.8+
- PostgreSQL 12+
- Docker & Docker Compose (optional)

## 🛠️ Installation

### Option 1: Docker (Recommended)

1. Clone the repository:
```bash
git clone <your-repo-url>
cd hadal2
```

2. Start the application:
```bash
docker-compose up -d
```

3. Apply database migrations:
```bash
docker-compose exec app alembic upgrade head
```

4. Access the application at `http://localhost:8000`

### Option 2: Local Development

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Set up PostgreSQL database and update `DATABASE_URL` in environment

3. Copy configuration files:
```bash
cp app/config.py.example app/config.py
cp crawler/config.py.example crawler/config.py
```

4. Update configuration with your settings

5. Run migrations:
```bash
alembic upgrade head
```

6. Start the application:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## 🔧 Configuration

### Environment Variables

- `DATABASE_URL`: PostgreSQL connection string
- `API_AUTH_TOKEN`: Authentication token for API endpoints
- `TELEGRAM_BOT_TOKEN`: Telegram bot token for notifications
- `TELEGRAM_CHAT_ID`: Telegram chat ID for notifications

### Security Notes

⚠️ **Important**: Before deploying to production:
- Change default API authentication tokens
- Update Telegram bot credentials
- Use environment variables for sensitive configuration
- Enable HTTPS in production

## 📊 Usage

### Web Interface

1. **Dashboard**: View recent network blocks and host responses
2. **Search**: Use advanced search with filters for IP, port, status, etc.
3. **Export**: Download results in JSON or CSV format
4. **API**: Access data programmatically via REST endpoints

### Crawler

The crawler component:
- Claims network blocks via `POST /claim-block`
- Scans IP addresses on ports 80 and 443
- Submits results via `POST /add-responses-batch`
- Supports concurrent scanning with configurable limits

### API Endpoints

- `GET /api/search` - Advanced search with filtering
- `POST /claim-block` - Claim a network block for scanning
- `POST /add-responses-batch` - Submit scan results in bulk
- `GET /api/stats` - Get application statistics

## 🗄️ Database

The application uses PostgreSQL with the following main tables:
- `network_blocks`: Network ranges to be scanned
- `host_responses`: Individual host scan results
- `alembic_version`: Migration tracking

## 🔍 Search Features

Advanced search capabilities include:
- **Real-time AJAX search** with debounced input
- **Multi-field filtering** (IP, port, status, banner, etc.)
- **Include/exclude filters** for each field
- **Date range filtering**
- **Sorting and pagination**
- **Export to JSON/CSV**

## 🐳 Docker

The application includes:
- `Dockerfile` for the main application
- `docker-compose.yml` for complete stack
- `nginx.conf` for reverse proxy configuration
- PostgreSQL data persistence

## 📈 Monitoring

- Application logs via Docker Compose
- Telegram notifications for errors and events
- Database query performance tracking
- Search execution timing

## 🔒 Security

- API token authentication
- SQL injection protection via parameterized queries
- Input validation and sanitization
- CORS configuration
- Security headers via Nginx

## 🚀 Development

### Running Tests
```bash
# Add your test commands here
```

### Database Migrations
```bash
# Create a new migration
docker-compose exec app alembic revision --autogenerate -m "Description"

# Apply migrations
docker-compose exec app alembic upgrade head

# Rollback migration
docker-compose exec app alembic downgrade -1
```

### Code Structure
```
├── app/                    # Main application
│   ├── main.py            # Starlette application
│   ├── models.py          # SQLAlchemy models
│   ├── search_logic.py    # Search functionality
│   ├── templates/         # Jinja2 templates
│   └── static/           # Static assets
├── crawler/               # Network scanner
│   ├── main.py           # Crawler logic
│   └── config.py         # Crawler configuration
├── docker-compose.yml     # Docker orchestration
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for authorized network reconnaissance and security research. Users are responsible for ensuring they have proper authorization before scanning any networks. The authors are not responsible for any misuse of this software.

## 🆘 Support

For issues and questions:
- Check the troubleshooting section below
- Review application logs
- Create an issue on GitHub

## 🔧 Troubleshooting

### Common Issues

1. **Database Connection Error**
   - Ensure PostgreSQL container is running: `docker-compose ps`
   - Check database logs: `docker-compose logs db`

2. **Migration Errors**
   - Reset database: `docker-compose down -v && docker-compose up -d`
   - Re-run migrations: `docker-compose exec app alembic upgrade head`

3. **Static Files Not Loading**
   - Check Nginx configuration
   - Verify static files are in the correct directory
   - Check Nginx logs: `docker-compose logs nginx`

### Performance Optimization

- Enable Nginx caching for static files
- Use database connection pooling
- Implement Redis for session storage (if needed)
- Add CDN for static assets in production
