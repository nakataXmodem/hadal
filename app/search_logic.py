import logging
import time
from typing import Optional, Dict, Any, List
from datetime import datetime
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, validator, Field
import ipaddress

logger = logging.getLogger(__name__)

# Input validation models
class SearchFilters(BaseModel):
    # Basic search
    query: Optional[str] = Field(None, max_length=100)
    
    # Field-specific searches
    ip_address: Optional[str] = Field(None, max_length=50)
    ip_address_exclude: Optional[str] = Field(None, max_length=50)
    port: Optional[int] = Field(None, ge=1, le=65535)
    port_exclude: Optional[int] = Field(None, ge=1, le=65535)
    status_code: Optional[int] = Field(None, ge=100, le=599)
    status_code_exclude: Optional[int] = Field(None, ge=100, le=599)
    # protocol: Optional[str] = Field(None, max_length=10)  # Not developed yet
    title: Optional[str] = Field(None, max_length=100)
    title_exclude: Optional[str] = Field(None, max_length=100)
    banner: Optional[str] = Field(None, max_length=100)
    banner_exclude: Optional[str] = Field(None, max_length=100)
    headers: Optional[str] = Field(None, max_length=100)
    headers_exclude: Optional[str] = Field(None, max_length=100)
    http_response: Optional[str] = Field(None, max_length=100)
    http_response_exclude: Optional[str] = Field(None, max_length=100)
    # certificate: Optional[str] = Field(None, max_length=100)  # Not developed yet
    # certificate_exclude: Optional[str] = Field(None, max_length=100)  # Not developed yet
    
    # Date range filters
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    
    # Sorting
    sort_by: Optional[str] = Field(None, pattern="^(ip_address|port|status_code|title|scan_timestamp|created_at)$")
    sort_order: Optional[str] = Field(None, pattern="^(asc|desc)$")
    
    # Pagination
    page: int = Field(1, ge=1)
    per_page: int = Field(20, ge=1, le=1000)
    
    # Active status filter - commented out since all records are active
    # is_active: Optional[bool] = None
    
    @validator('ip_address', 'ip_address_exclude')
    def validate_ip_address(cls, v):
        if v:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError('Invalid IP address format')
        return v
    
    @validator('date_from', 'date_to')
    def validate_date_format(cls, v):
        if v:
            try:
                datetime.strptime(v, '%Y-%m-%d')
            except ValueError:
                raise ValueError('Date must be in YYYY-MM-DD format')
        return v

def build_search_query(filters: SearchFilters) -> tuple[str, dict]:
    """Build parameterized SQL query with filters"""
    base_query = """
        SELECT id, ip_address, port, is_active, protocol,
               banner, http_response, headers, certificate,
               scan_timestamp, created_at, status_code, title, icon_hash
        FROM host_responses
        WHERE 1=1
    """
    
    params = {}
    conditions = []
    
    # Basic search across multiple fields
    if filters.query:
        conditions.append("""
            (ip_address::text ILIKE :query 
             OR banner ILIKE :query 
             OR http_response ILIKE :query 
             OR headers ILIKE :query 
             OR title ILIKE :query)
        """)
        params['query'] = f"%{filters.query}%"
    
    # Field-specific searches
    if filters.ip_address:
        conditions.append("ip_address::text ILIKE :ip_address")
        params['ip_address'] = f"%{filters.ip_address}%"
    
    if filters.ip_address_exclude:
        conditions.append("ip_address::text NOT ILIKE :ip_address_exclude")
        params['ip_address_exclude'] = f"%{filters.ip_address_exclude}%"
    
    if filters.port:
        conditions.append("port = :port")
        params['port'] = filters.port
    
    if filters.port_exclude:
        conditions.append("port != :port_exclude")
        params['port_exclude'] = filters.port_exclude
    
    if filters.status_code:
        conditions.append("status_code = :status_code")
        params['status_code'] = filters.status_code
    
    if filters.status_code_exclude:
        conditions.append("status_code != :status_code_exclude")
        params['status_code_exclude'] = filters.status_code_exclude
    
    # if filters.protocol:
    #     conditions.append("protocol ILIKE :protocol")
    #     params['protocol'] = f"%{filters.protocol}%"
    
    if filters.title:
        conditions.append("title ILIKE :title")
        params['title'] = f"%{filters.title}%"
    
    if filters.title_exclude:
        conditions.append("title NOT ILIKE :title_exclude")
        params['title_exclude'] = f"%{filters.title_exclude}%"
    
    if filters.banner:
        conditions.append("banner ILIKE :banner")
        params['banner'] = f"%{filters.banner}%"
    
    if filters.banner_exclude:
        conditions.append("banner NOT ILIKE :banner_exclude")
        params['banner_exclude'] = f"%{filters.banner_exclude}%"
    
    if filters.headers:
        conditions.append("headers ILIKE :headers")
        params['headers'] = f"%{filters.headers}%"
    
    if filters.headers_exclude:
        conditions.append("headers NOT ILIKE :headers_exclude")
        params['headers_exclude'] = f"%{filters.headers_exclude}%"
    
    if filters.http_response:
        conditions.append("http_response ILIKE :http_response")
        params['http_response'] = f"%{filters.http_response}%"
    
    if filters.http_response_exclude:
        conditions.append("http_response NOT ILIKE :http_response_exclude")
        params['http_response_exclude'] = f"%{filters.http_response_exclude}%"
    
    # if filters.certificate:
    #     conditions.append("certificate ILIKE :certificate")
    #     params['certificate'] = f"%{filters.certificate}%"
    
    # if filters.certificate_exclude:
    #     conditions.append("certificate NOT ILIKE :certificate_exclude")
    #     params['certificate_exclude'] = f"%{filters.certificate_exclude}%"
    
    # Date range filters
    if filters.date_from:
        conditions.append("scan_timestamp >= :date_from")
        params['date_from'] = f"{filters.date_from} 00:00:00"
    
    if filters.date_to:
        conditions.append("scan_timestamp <= :date_to")
        params['date_to'] = f"{filters.date_to} 23:59:59"
    
    # Active status filter - commented out since all records are active
    # if filters.is_active is not None:
    #     conditions.append("is_active = :is_active")
    #     params['is_active'] = filters.is_active
    
    # Build final query
    if conditions:
        base_query += " AND " + " AND ".join(conditions)
    
    # Sorting
    sort_field = filters.sort_by or "scan_timestamp"
    sort_direction = filters.sort_order or "desc"
    base_query += f" ORDER BY {sort_field} {sort_direction.upper()}"
    
    # Pagination
    base_query += " LIMIT :limit OFFSET :offset"
    params['limit'] = filters.per_page
    params['offset'] = (filters.page - 1) * filters.per_page
    
    return base_query, params

def build_count_query(filters: SearchFilters) -> tuple[str, dict]:
    """Build count query with same filters"""
    base_query = "SELECT COUNT(*) FROM host_responses WHERE 1=1"
    
    params = {}
    conditions = []
    
    # Apply same filtering logic as search query (without pagination)
    if filters.query:
        conditions.append("""
            (ip_address::text ILIKE :query 
             OR banner ILIKE :query 
             OR http_response ILIKE :query 
             OR headers ILIKE :query 
             OR title ILIKE :query)
        """)
        params['query'] = f"%{filters.query}%"
    
    # Add all other conditions (same as build_search_query but without pagination params)
    if filters.ip_address:
        conditions.append("ip_address::text ILIKE :ip_address")
        params['ip_address'] = f"%{filters.ip_address}%"
    
    if filters.ip_address_exclude:
        conditions.append("ip_address::text NOT ILIKE :ip_address_exclude")
        params['ip_address_exclude'] = f"%{filters.ip_address_exclude}%"
    
    if filters.port:
        conditions.append("port = :port")
        params['port'] = filters.port
    
    if filters.port_exclude:
        conditions.append("port != :port_exclude")
        params['port_exclude'] = filters.port_exclude
    
    if filters.status_code:
        conditions.append("status_code = :status_code")
        params['status_code'] = filters.status_code
    
    if filters.status_code_exclude:
        conditions.append("status_code != :status_code_exclude")
        params['status_code_exclude'] = filters.status_code_exclude
    
    # if filters.protocol:
    #     conditions.append("protocol ILIKE :protocol")
    #     params['protocol'] = f"%{filters.protocol}%"
    
    if filters.title:
        conditions.append("title ILIKE :title")
        params['title'] = f"%{filters.title}%"
    
    if filters.title_exclude:
        conditions.append("title NOT ILIKE :title_exclude")
        params['title_exclude'] = f"%{filters.title_exclude}%"
    
    if filters.banner:
        conditions.append("banner ILIKE :banner")
        params['banner'] = f"%{filters.banner}%"
    
    if filters.banner_exclude:
        conditions.append("banner NOT ILIKE :banner_exclude")
        params['banner_exclude'] = f"%{filters.banner_exclude}%"
    
    if filters.headers:
        conditions.append("headers ILIKE :headers")
        params['headers'] = f"%{filters.headers}%"
    
    if filters.headers_exclude:
        conditions.append("headers NOT ILIKE :headers_exclude")
        params['headers_exclude'] = f"%{filters.headers_exclude}%"
    
    if filters.http_response:
        conditions.append("http_response ILIKE :http_response")
        params['http_response'] = f"%{filters.http_response}%"
    
    if filters.http_response_exclude:
        conditions.append("http_response NOT ILIKE :http_response_exclude")
        params['http_response_exclude'] = f"%{filters.http_response_exclude}%"
    
    # if filters.certificate:
    #     conditions.append("certificate ILIKE :certificate")
    #     params['certificate'] = f"%{filters.certificate}%"
    
    # if filters.certificate_exclude:
    #     conditions.append("certificate NOT ILIKE :certificate_exclude")
    #     params['certificate_exclude'] = f"%{filters.certificate_exclude}%"
    
    if filters.date_from:
        conditions.append("scan_timestamp >= :date_from")
        params['date_from'] = f"{filters.date_from} 00:00:00"
    
    if filters.date_to:
        conditions.append("scan_timestamp <= :date_to")
        params['date_to'] = f"{filters.date_to} 23:59:59"
    
    # Active status filter - commented out since all records are active
    # if filters.is_active is not None:
    #     conditions.append("is_active = :is_active")
    #     params['is_active'] = filters.is_active
    
    if conditions:
        base_query += " AND " + " AND ".join(conditions)
    
    return base_query, params

async def execute_search(filters: SearchFilters, session: AsyncSession) -> Dict[str, Any]:
    """Execute search and return results with timing information"""
    start_time = time.time()
    
    try:
        # Build queries
        search_query, search_params = build_search_query(filters)
        count_query, count_params = build_count_query(filters)
        
        # Get total count
        count_start = time.time()
        result = await session.execute(text(count_query), count_params)
        total_count = result.scalar()
        count_time = (time.time() - count_start) * 1000
        
        # Get paginated results
        search_start = time.time()
        result = await session.execute(text(search_query), search_params)
        host_responses = result.fetchall()
        search_time = (time.time() - search_start) * 1000
        
        # Convert to list of dictionaries
        responses = []
        for row in host_responses:
            ip_address = row[1]
            port = row[2]
            
            if port == 80:
                proto = 'http'
            elif port == 443:
                proto = 'https'
            else:
                proto = 'http'  # default
            
            responses.append({
                'id': row[0],
                'ip_address': str(row[1]),
                'port': row[2],
                'is_active': row[3],
                'protocol': row[4],
                'banner': row[5][:100] + "..." if row[5] and len(row[5]) > 100 else row[5],
                'http_response': row[6][:100] + "..." if row[6] and len(row[6]) > 100 else row[6],
                'headers': row[7][:100] + "..." if row[7] and len(row[7]) > 100 else row[7],
                'scan_timestamp': row[9].strftime('%Y-%m-%d %H:%M:%S') if row[9] else None,
                'created_at': row[10].strftime('%Y-%m-%d %H:%M:%S') if row[10] else None,
                'status_code': row[11],
                'title': row[12][:100] + "..." if row[12] and len(row[12]) > 100 else row[12],
                'icon_hash': row[13],
                "url": f'{proto}://{ip_address}'
            })
        
        # Calculate pagination
        total_pages = (total_count + filters.per_page - 1) // filters.per_page
        has_prev = filters.page > 1
        has_next = filters.page < total_pages
        
        total_time = (time.time() - start_time) * 1000
        
        return {
            "success": True,
            "data": responses,
            "pagination": {
                "page": filters.page,
                "per_page": filters.per_page,
                "total_count": total_count,
                "total_pages": total_pages,
                "has_prev": has_prev,
                "has_next": has_next,
                "prev_page": filters.page - 1 if has_prev else None,
                "next_page": filters.page + 1 if has_next else None
            },
            "timing": {
                "total_ms": round(total_time, 2),
                "count_ms": round(count_time, 2),
                "search_ms": round(search_time, 2)
            }
        }
        
    except Exception as e:
        logger.error(f"Search error: {e}")
        return {
            "success": False,
            "error": str(e),
            "data": [],
            "pagination": {"total_count": 0, "page": 1},
            "timing": {"total_ms": 0, "count_ms": 0, "search_ms": 0}
        }

def parse_search_params(query_params: dict) -> SearchFilters:
    """Parse and validate query parameters"""
    # Create a copy to avoid modifying the original
    params = query_params.copy()
    
    # Remove empty string values for integer fields
    integer_fields = ['port', 'port_exclude', 'status_code', 'status_code_exclude', 'page', 'per_page']
    for field in integer_fields:
        if field in params and (params[field] == '' or params[field] is None):
            params.pop(field, None)
    
    # Convert string values to appropriate types
    if 'port' in params and params['port']:
        params['port'] = int(params['port'])
    if 'port_exclude' in params and params['port_exclude']:
        params['port_exclude'] = int(params['port_exclude'])
    if 'status_code' in params and params['status_code']:
        params['status_code'] = int(params['status_code'])
    if 'status_code_exclude' in params and params['status_code_exclude']:
        params['status_code_exclude'] = int(params['status_code_exclude'])
    if 'page' in params:
        params['page'] = int(params['page'])
    if 'per_page' in params:
        params['per_page'] = int(params['per_page'])
    # Commented out is_active logic since all records are active
    # if 'is_active' in params and params['is_active']:
    #     params['is_active'] = params['is_active'].lower() in ('true', '1', 'yes')
    # elif 'is_active' in params and params['is_active'] == '':
    #     params.pop('is_active', None)
    
    # Validate filters
    return SearchFilters(**params)
