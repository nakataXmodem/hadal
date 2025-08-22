# Advanced Search Features

## Overview

The Hadal application now includes a comprehensive advanced search system with the following features:

- **Advanced Filtering**: Search by specific fields with include/exclude options
- **Real-time AJAX Search**: Instant results with debounced input
- **Query Performance Timing**: See how long queries take to execute
- **Flexible Result Counts**: Choose from 10 to 500 results per page
- **Multiple Export Formats**: JSON and CSV export options
- **RESTful API**: Use search functionality in other applications
- **SQL Injection Protection**: Parameterized queries with input validation
- **Performance Optimized**: Database indexes for fast queries

## Search Interface

### Basic Search
- **Quick Search**: Search across all fields (IP, banner, headers, HTTP response, certificate, title)
- **Real-time Results**: Results update automatically as you type (with 500ms debounce)

### Advanced Filters

#### IP Address
- **Include**: Filter by specific IP addresses or patterns
- **Exclude**: Exclude specific IP addresses or patterns

#### Port
- **Include**: Filter by specific port numbers
- **Exclude**: Exclude specific port numbers

#### Status Code
- **Include**: Filter by HTTP status codes (100-599)
- **Exclude**: Exclude specific status codes

#### Protocol
- Filter by protocol type (tcp, http, https, etc.)

#### Title
- **Include**: Filter by page titles
- **Exclude**: Exclude specific titles

#### Banner
- **Include**: Filter by service banners
- **Exclude**: Exclude specific banners

#### Headers
- **Include**: Filter by HTTP headers
- **Exclude**: Exclude specific headers

#### HTTP Response
- **Include**: Filter by HTTP response content
- **Exclude**: Exclude specific response content

#### Certificate
- **Include**: Filter by SSL certificate content
- **Exclude**: Exclude specific certificate content

#### Date Range
- **From**: Start date (YYYY-MM-DD format)
- **To**: End date (YYYY-MM-DD format)

#### Active Status
- **All**: Show all responses
- **Active Only**: Show only active responses
- **Inactive Only**: Show only inactive responses

### Sorting Options
- **Sort By**: IP Address, Port, Status Code, Title, Scan Time, Created Time
- **Sort Order**: Ascending or Descending

### Results Per Page
- Options: 10, 20, 50, 100, 200, 500 results

## API Endpoints

### Search API
```
GET /api/search
POST /api/search
```

**Parameters:**
- All filter parameters from the web interface
- `page`: Page number (default: 1)
- `per_page`: Results per page (default: 20, max: 1000)

**Response Format:**
```json
{
  "success": true,
  "data": [
    {
      "id": 123,
      "ip_address": "192.168.1.1",
      "port": 80,
      "is_active": true,
      "protocol": "tcp",
      "banner": "Apache/2.4.41",
      "http_response": "Welcome to Apache",
      "headers": "Server: Apache/2.4.41",
      "scan_timestamp": "2024-01-01 12:00:00",
      "created_at": "2024-01-01 12:00:00",
      "status_code": 200,
      "title": "Welcome to Apache",
      "icon_hash": "abc123",
      "url": "http://192.168.1.1"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total_count": 1000,
    "total_pages": 50,
    "has_prev": false,
    "has_next": true,
    "prev_page": null,
    "next_page": 2
  },
  "timing": {
    "total_ms": 45.23,
    "count_ms": 12.45,
    "search_ms": 32.78
  }
}
```

### Export API
```
GET /api/search/export
POST /api/search/export
```

**Parameters:**
- Same as search API
- Automatically sets `per_page` to 1000 for export

**Response:**
- CSV file download with filename: `host_responses_export_YYYYMMDD_HHMMSS.csv`

## Example API Usage

### Basic Search
```bash
curl "http://localhost:8000/api/search?query=apache&per_page=50"
```

### Advanced Filtering
```bash
curl "http://localhost:8000/api/search?ip_address=192.168.1&port=80&status_code=200&sort_by=scan_timestamp&sort_order=desc"
```

### JSON Export
```bash
curl "http://localhost:8000/api/search?query=nginx&per_page=1000" > results.json
```

### CSV Export
```bash
curl "http://localhost:8000/api/search/export?query=apache" -o export.csv
```

## Security Features

### Input Validation
- **Pydantic Models**: All input is validated using Pydantic
- **Type Checking**: Automatic type conversion and validation
- **Length Limits**: Maximum field lengths enforced
- **IP Validation**: IP address format validation
- **Date Validation**: Date format validation (YYYY-MM-DD)

### SQL Injection Protection
- **Parameterized Queries**: All user input uses parameterized queries
- **Input Sanitization**: Null byte removal and length limiting
- **Field Whitelisting**: Only allowed fields can be sorted

### Rate Limiting
- **Query Limits**: Maximum 1000 results per request
- **Input Limits**: Maximum 100 characters for text fields

## Performance Optimizations

### Database Indexes
The following indexes are created for optimal performance:

```sql
-- Basic indexes
CREATE INDEX idx_host_responses_ip_port ON host_responses(ip_address, port);
CREATE INDEX idx_host_responses_scan_timestamp ON host_responses(scan_timestamp);
CREATE INDEX idx_host_responses_is_active ON host_responses(is_active);
CREATE INDEX idx_host_responses_status_code ON host_responses(status_code);

-- Composite indexes for common queries
CREATE INDEX idx_host_responses_active_timestamp ON host_responses(is_active, scan_timestamp);
CREATE INDEX idx_host_responses_ip_timestamp ON host_responses(ip_address, scan_timestamp);

-- Text search indexes (PostgreSQL)
CREATE INDEX idx_host_responses_banner_text ON host_responses USING gin(to_tsvector('english', banner));
CREATE INDEX idx_host_responses_title_text ON host_responses USING gin(to_tsvector('english', title));
```

### Query Optimization
- **Separate Count Queries**: Count and data queries are optimized separately
- **Efficient Pagination**: Uses LIMIT/OFFSET with proper indexing
- **Conditional WHERE Clauses**: Only applies filters when provided

## Installation and Setup

### 1. Apply Database Indexes
```bash
# Connect to your PostgreSQL database and run:
psql -d webapp_stats -f app/create_indexes.sql
```

### 2. Restart Application
```bash
docker compose restart app
```

### 3. Test the Search
- Navigate to `/search` in your browser
- Try the advanced filters
- Test the API endpoints

## Troubleshooting

### Common Issues

1. **Slow Queries**: Ensure database indexes are created
2. **No Results**: Check filter parameters and data availability
3. **API Errors**: Verify parameter types and validation rules
4. **Export Issues**: Check file permissions and disk space

### Performance Monitoring
- Query timing is displayed in the UI
- Check database query logs for slow queries
- Monitor database connection pool usage

## Future Enhancements

- **Full-text Search**: PostgreSQL full-text search integration
- **Saved Searches**: User-defined search templates
- **Advanced Analytics**: Search result analytics and trends
- **Real-time Updates**: WebSocket integration for live results
- **Search Suggestions**: Autocomplete for common search terms
