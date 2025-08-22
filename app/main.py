import os
import asyncio
import logging
from datetime import datetime
from contextlib import asynccontextmanager
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette.requests import Request
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text, func
from typing import Optional, Dict, Any, List
import re
from datetime import datetime, timedelta
from sqlalchemy import and_, or_, desc, asc, not_, func
from sqlalchemy.sql import text
import csv
import io

from models import NetworkBlock, HostResponse
from database import get_db_session
from config import NOTIFY_ON_STARLETTE_ERRORS
from telegram_notifier import telegram_notifier
from middleware import AuthTokenMiddleware, ErrorHandlingMiddleware
from search_logic import execute_search, parse_search_params

# Import shared database engine
from database import engine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Templates setup
templates = Jinja2Templates(directory="templates")

def sanitize_and_limit(value, limit: int):
    if not isinstance(value, str):
        return None
    value = value.replace("\x00", "")
    return value[:limit]

@asynccontextmanager
async def lifespan(app: Starlette):
    # Startup
    logger.info("Starting up...")
    if telegram_notifier.enabled:
        await telegram_notifier.send_message("🚀 <b>Hadal Application Started</b>\n\nApplication is now running and ready to process requests.")
    yield
    # Shutdown
    logger.info("Shutting down...")
    if telegram_notifier.enabled:
        await telegram_notifier.send_message("🛑 <b>Hadal Application Shutting Down</b>\n\nApplication is stopping.")
    await engine.dispose()

# Create Starlette app
app = Starlette(
    debug=True,
    lifespan=lifespan
)

# Add middleware
app.add_middleware(ErrorHandlingMiddleware)
app.add_middleware(AuthTokenMiddleware)

# Mount static files - commented out since nginx serves static files directly
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.route("/")
async def index(request: Request):
    """Main page showing network scanning data"""
    async with get_db_session() as session:
        # Get network blocks data
        result = await session.execute(text("SELECT * FROM network_blocks ORDER BY created_at DESC LIMIT 10"))
        network_blocks = result.fetchall()

        # Get host responses data (explicit column order)
        result = await session.execute(text(
            """
            SELECT id, ip_address, port, is_active, protocol,
                   banner, http_response, headers, certificate,
                   scan_timestamp, created_at, status_code, title, icon_hash
            FROM host_responses
            ORDER BY scan_timestamp DESC
            LIMIT 24
            """
        ))
        host_responses = result.fetchall()
        
        # Convert network blocks to list of dictionaries for template
        blocks = []
        for row in network_blocks:
            blocks.append({
                'id': row[0],
                'network': str(row[1]),
                'status': row[2],
                'assigned_to': row[3],
                'last_assigned': row[4].strftime('%Y-%m-%d %H:%M:%S') if row[4] else None,
                'created_at': row[5].strftime('%Y-%m-%d %H:%M:%S') if row[5] else None,
                'updated_at': row[6].strftime('%Y-%m-%d %H:%M:%S') if row[6] else None
            })
        
        # Convert host responses to list of dictionaries for template
        responses = []
        for row in host_responses:
            responses.append({
                'id': row[0],
                'ip_address': str(row[1]),
                'port': row[2],
                'is_active': row[3],
                'protocol': row[4],
                'banner': row[5],
                'http_response': row[6],
                'headers': row[7],
                'certificate': row[8],
                'scan_timestamp': row[9].strftime('%Y-%m-%d %H:%M:%S') if row[9] else None,
                'created_at': row[10].strftime('%Y-%m-%d %H:%M:%S') if row[10] else None,
                'status_code': row[11],
                'title': row[12],
                'icon_hash': row[13]
            })
        
        # Calculate summary statistics
        total_blocks = len(blocks)
        completed_blocks = len([b for b in blocks if b['status'] == 'COMPLETED'])
        pending_blocks = len([b for b in blocks if b['status'] == 'PENDING'])
        active_responses = len([r for r in responses if r['is_active']])
        total_responses = len(responses)
        
        context = {
            "request": request,
            "network_blocks": blocks,
            "host_responses": responses,
            "summary": {
                "total_blocks": total_blocks,
                "completed_blocks": completed_blocks,
                "pending_blocks": pending_blocks,
                "active_responses": active_responses,
                "total_responses": total_responses
            }
        }
        
        return templates.TemplateResponse("index.html", context)

@app.route("/search")
async def search_host_responses(request: Request):
    """Search page for host responses with advanced filtering"""
    try:
        # Parse and validate query parameters
        query_params = dict(request.query_params)
        filters = parse_search_params(query_params)
        
    except Exception as e:
        # Return error for invalid parameters
        return templates.TemplateResponse("search.html", {
            "request": request,
            "error": f"Invalid search parameters: {str(e)}",
            "host_responses": [],
            "pagination": {"total_count": 0, "page": 1},
            "timing": {"total_ms": 0, "count_ms": 0, "search_ms": 0},
            "filters": {}
        })
    
    async with get_db_session() as session:
        try:
            # Execute search
            result = await execute_search(filters, session)
            
            if result["success"]:
                context = {
                    "request": request,
                    "host_responses": result["data"],
                    "pagination": result["pagination"],
                    "timing": result["timing"],
                    "filters": filters.dict(),
                    "error": None
                }
            else:
                context = {
                    "request": request,
                    "error": result["error"],
                    "host_responses": [],
                    "pagination": {"total_count": 0, "page": 1},
                    "timing": {"total_ms": 0, "count_ms": 0, "search_ms": 0},
                    "filters": filters.dict()
                }
            
            return templates.TemplateResponse("search.html", context)
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            return templates.TemplateResponse("search.html", {
                "request": request,
                "error": "An error occurred while searching",
                "host_responses": [],
                "pagination": {"total_count": 0, "page": 1},
                "timing": {"total_ms": 0, "count_ms": 0, "search_ms": 0},
                "filters": {}
            })

@app.route("/api/search", methods=["GET", "POST"])
async def api_search_host_responses(request: Request):
    """API endpoint for searching host responses with advanced filtering"""
    try:
        # Parse parameters from either GET query params or POST JSON body
        if request.method == "GET":
            query_params = dict(request.query_params)
        else:
            body = await request.json()
            query_params = body if isinstance(body, dict) else {}
        
        # Parse and validate filters
        filters = parse_search_params(query_params)
        
        # Execute search
        async with get_db_session() as session:
            result = await execute_search(filters, session)
        
        return JSONResponse(result)
        
    except Exception as e:
        logger.error(f"API search error: {e}")
        return JSONResponse({
            "success": False,
            "error": f"Invalid search parameters: {str(e)}",
            "data": [],
            "pagination": {"total_count": 0, "page": 1},
            "timing": {"total_ms": 0, "count_ms": 0, "search_ms": 0}
        }, status_code=400)

@app.route("/api/search/export", methods=["GET", "POST"])
async def api_search_export(request: Request):
    """API endpoint for exporting search results in CSV format"""
    try:
        # Parse parameters from either GET query params or POST JSON body
        if request.method == "GET":
            query_params = dict(request.query_params)
        else:
            body = await request.json()
            query_params = body if isinstance(body, dict) else {}
        
        # For export, we want more results
        if 'per_page' not in query_params or query_params['per_page'] < 1000:
            query_params['per_page'] = 1000
        
        # Parse and validate filters
        filters = parse_search_params(query_params)
        
        # Execute search
        async with get_db_session() as session:
            result = await execute_search(filters, session)
        
        if not result["success"]:
            return JSONResponse({
                "success": False,
                "error": result["error"]
            }, status_code=400)
        
        # Generate CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'ID', 'IP Address', 'Port', 'Is Active', 'Protocol', 'Status Code',
            'Title', 'Banner', 'Headers', 'HTTP Response', 'Certificate',
            'Icon Hash', 'Scan Timestamp', 'Created At', 'URL'
        ])
        
        # Write data rows
        for row in result["data"]:
            writer.writerow([
                row['id'],
                row['ip_address'],
                row['port'],
                row['is_active'],
                row['protocol'],
                row['status_code'],
                row['title'] or '',
                row['banner'] or '',
                row['headers'] or '',
                row['http_response'] or '',
                '',  # certificate field not in current data
                row['icon_hash'] or '',
                row['scan_timestamp'] or '',
                row['created_at'] or '',
                row['url']
            ])
        
        csv_content = output.getvalue()
        output.close()
        
        # Return CSV file
        from starlette.responses import Response
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=host_responses_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            }
        )
        
    except Exception as e:
        logger.error(f"CSV export error: {e}")
        return JSONResponse({
            "success": False,
            "error": f"Export failed: {str(e)}"
        }, status_code=400)

@app.route("/network-blocks")
async def network_blocks(request: Request):
    """Network blocks statistics and current processing status"""
    page = int(request.query_params.get("page", 1))
    per_page = 15
    offset = (page - 1) * per_page
    
    async with get_db_session() as session:
        # Get statistics
        stats_result = await session.execute(text("""
            SELECT 
                COUNT(*) as total_blocks,
                COUNT(CASE WHEN status = 'COMPLETED' THEN 1 END) as completed_blocks,
                COUNT(CASE WHEN status = 'PENDING' THEN 1 END) as pending_blocks,
                COUNT(CASE WHEN status = 'IN_PROGRESS' THEN 1 END) as in_progress_blocks,
                COUNT(CASE WHEN status = 'FAILED' THEN 1 END) as failed_blocks,
                AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/3600) as avg_processing_hours
            FROM network_blocks
        """))
        stats = stats_result.fetchone()
        
        # Get currently processing blocks
        processing_result = await session.execute(text("""
            SELECT * FROM network_blocks 
            WHERE status IN ('PENDING', 'IN_PROGRESS')
            ORDER BY created_at ASC
            LIMIT :limit OFFSET :offset
        """), {"limit": per_page, "offset": offset})
        processing_blocks = processing_result.fetchall()
        
        # Get total count of processing blocks
        count_result = await session.execute(text("""
            SELECT COUNT(*) FROM network_blocks 
            WHERE status IN ('PENDING', 'IN_PROGRESS')
        """))
        total_processing = count_result.scalar()
        
        # Convert to list of dictionaries
        blocks = []
        for row in processing_blocks:
            blocks.append({
                'id': row[0],
                'network': str(row[1]),
                'status': row[2],
                'assigned_to': row[3],
                'last_assigned': row[4].strftime('%Y-%m-%d %H:%M:%S') if row[4] else None,
                'created_at': row[5].strftime('%Y-%m-%d %H:%M:%S') if row[5] else None,
                'updated_at': row[6].strftime('%Y-%m-%d %H:%M:%S') if row[6] else None
            })
        
        # Calculate pagination
        total_pages = (total_processing + per_page - 1) // per_page
        has_prev = page > 1
        has_next = page < total_pages
        
        context = {
            "request": request,
            "blocks": blocks,
            "statistics": {
                "total_blocks": stats[0],
                "completed_blocks": stats[1],
                "pending_blocks": stats[2],
                "in_progress_blocks": stats[3],
                "failed_blocks": stats[4],
                "avg_processing_hours": round(stats[5], 2) if stats[5] else 0
            },
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total_count": total_processing,
                "total_pages": total_pages,
                "has_prev": has_prev,
                "has_next": has_next,
                "prev_page": page - 1 if has_prev else None,
                "next_page": page + 1 if has_next else None
            }
        }
        
        return templates.TemplateResponse("network_blocks.html", context)

@app.route("/add-block", methods=["POST"])
async def add_network_block(request: Request):
    """Add a new network block"""
    form = await request.form()
    
    async with get_db_session() as session:
        new_block = NetworkBlock(
            network=form.get("network"),
            status=form.get("status", "PENDING"),
            assigned_to=form.get("assigned_to") if form.get("assigned_to") else None
        )
        session.add(new_block)
        await session.commit()
    
    return HTMLResponse("Network block added successfully! <a href='/'>Back to home</a>")

@app.route("/add-response", methods=["POST"])
async def add_host_response(request: Request):
    """Add a new host response"""
    form = await request.form()
    
    async with get_db_session() as session:
        # Apply reasonable limits consistent with model definitions
        BANNER_LIMIT = 512
        HTTP_LIMIT = 8192
        HEADERS_LIMIT = 4096
        CERT_LIMIT = 8192
        banner = sanitize_and_limit(form.get("banner"), BANNER_LIMIT)
        http_response = sanitize_and_limit(form.get("http_response"), HTTP_LIMIT)
        headers = sanitize_and_limit(form.get("headers"), HEADERS_LIMIT)
        certificate = sanitize_and_limit(form.get("certificate"), CERT_LIMIT)
        title = sanitize_and_limit(form.get("title"), 512)
        icon_hash = sanitize_and_limit(form.get("icon_hash"), 32)

        # Skip insert if marked inactive (no response)
        if form.get("is_active") not in ("true", True):
            return HTMLResponse("Skipped: no response", status_code=200)

        new_response = HostResponse(
            ip_address=form.get("ip_address"),
            port=int(form.get("port", 0)),
            is_active=form.get("is_active") == "true",
            protocol=form.get("protocol", "tcp"),
            banner=banner,
            http_response=http_response,
            headers=headers,
            certificate=certificate,
            title=title,
            icon_hash=icon_hash,
            scan_timestamp=datetime.utcnow()
        )
        session.add(new_response)
        await session.commit()
    
    return HTMLResponse("Host response added successfully! <a href='/'>Back to home</a>")

@app.route("/add-responses-batch", methods=["POST"])
async def add_host_responses_batch(request: Request):
    """Add multiple host responses in a single request.

    Accepts either a JSON array of response objects or an object with a 'responses' key.
    Each item may contain: ip_address, port, is_active, protocol, banner, http_response, headers, certificate.
    """
    payload = await request.json()
    if isinstance(payload, list):
        items = payload
    else:
        items = payload.get("responses", []) if isinstance(payload, dict) else []

    if not isinstance(items, list) or not items:
        return JSONResponse({"detail": "No responses provided"}, status_code=400)

    BANNER_LIMIT = 512
    HTTP_LIMIT = 8192
    HEADERS_LIMIT = 4096
    CERT_LIMIT = 8192

    objects = []
    for it in items:
        try:
            ip_address = it.get("ip_address")
            port = int(it.get("port", 0))
            is_active = bool(it.get("is_active", False))
            protocol = it.get("protocol", "tcp")
            banner = sanitize_and_limit(it.get("banner"), BANNER_LIMIT)
            http_response = sanitize_and_limit(it.get("http_response"), HTTP_LIMIT)
            headers = sanitize_and_limit(it.get("headers"), HEADERS_LIMIT)
            certificate = sanitize_and_limit(it.get("certificate"), CERT_LIMIT)
            status_code = it.get("status_code")
            title = sanitize_and_limit(it.get("title"), 512)
            icon_hash = sanitize_and_limit(it.get("icon_hash"), 32)
            if not ip_address or port <= 0:
                continue
            # Skip no-response entries
            if not is_active:
                continue
            obj = HostResponse(
                ip_address=ip_address,
                port=port,
                is_active=is_active,
                protocol=protocol,
                banner=banner,
                http_response=http_response,
                headers=headers,
                certificate=certificate,
                scan_timestamp=datetime.utcnow(),
                status_code=int(status_code) if isinstance(status_code, int) or (isinstance(status_code, str) and status_code.isdigit()) else None,
                title=title,
                icon_hash=icon_hash,
            )
            objects.append(obj)
        except Exception:
            continue

    if not objects:
        return JSONResponse({"detail": "No valid responses to insert"}, status_code=400)

    async with get_db_session() as session:
        session.add_all(objects)
        await session.commit()

    return JSONResponse({"inserted": len(objects)})

@app.route("/update-block-status", methods=["POST"])
async def update_block_status(request: Request):
    """Update a network block status to COMPLETED or FAILED.

    Body: {"id": <block_id>, "status": "COMPLETED"|"FAILED"}
    """
    body = await request.json()
    block_id = body.get("id")
    status = body.get("status")
    if not block_id or status not in ("COMPLETED", "FAILED"):
        return JSONResponse({"detail": "id and valid status required"}, status_code=400)

    async with get_db_session() as session:
        result = await session.execute(text(
            """
            UPDATE network_blocks
            SET status = :status,
                updated_at = NOW()
            WHERE id = :id
            RETURNING id, network::text, status, assigned_to, last_assigned, created_at, updated_at
            """
        ), {"id": block_id, "status": status})
        row = result.fetchone()
        if not row:
            await session.rollback()
            return JSONResponse({"detail": "block not found"}, status_code=404)
        await session.commit()
        return JSONResponse({
            "id": row[0],
            "network": row[1],
            "status": row[2],
            "assigned_to": row[3],
            "last_assigned": row[4].strftime('%Y-%m-%d %H:%M:%S') if row[4] else None,
            "created_at": row[5].strftime('%Y-%m-%d %H:%M:%S') if row[5] else None,
            "updated_at": row[6].strftime('%Y-%m-%d %H:%M:%S') if row[6] else None,
        })

@app.route("/claim-block", methods=["POST"])
async def claim_block(request: Request):
    """Claim the next PENDING network block atomically and mark it IN_PROGRESS.

    - Sets assigned_to to the requester's IP (X-Real-IP/X-Forwarded-For fallback to client host)
    - Updates last_assigned to NOW()
    - Sets status to IN_PROGRESS
    """
    # Determine requester IP
    x_real_ip = request.headers.get("x-real-ip")
    x_forwarded_for = request.headers.get("x-forwarded-for")
    client_ip = None
    if x_real_ip:
        client_ip = x_real_ip
    elif x_forwarded_for:
        client_ip = x_forwarded_for.split(",")[0].strip()
    else:
        client_ip = request.client.host if request.client else None

    async with get_db_session() as session:
        # Use SKIP LOCKED to avoid race conditions across concurrent claimers
        result = await session.execute(text(
            """
            WITH next_block AS (
                SELECT id
                FROM network_blocks
                WHERE status = 'PENDING'
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            UPDATE network_blocks nb
            SET status = 'IN_PROGRESS',
                assigned_to = :client_ip,
                last_assigned = NOW(),
                updated_at = NOW()
            FROM next_block
            WHERE nb.id = next_block.id
            RETURNING nb.id, nb.network::text, nb.status, nb.assigned_to, nb.last_assigned, nb.created_at, nb.updated_at
            """
        ), {"client_ip": client_ip})

        row = result.fetchone()
        if not row:
            # Nothing to claim
            return JSONResponse({"detail": "No PENDING blocks available"}, status_code=404)

        await session.commit()

        return JSONResponse({
            "id": row[0],
            "network": row[1],
            "status": row[2],
            "assigned_to": row[3],
            "last_assigned": row[4].strftime('%Y-%m-%d %H:%M:%S') if row[4] else None,
            "created_at": row[5].strftime('%Y-%m-%d %H:%M:%S') if row[5] else None,
            "updated_at": row[6].strftime('%Y-%m-%d %H:%M:%S') if row[6] else None,
        })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
