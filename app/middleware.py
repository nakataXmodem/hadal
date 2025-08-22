import logging
from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware
from config import API_AUTH_TOKEN, API_AUTH_ENABLED, DEVELOPMENT_MODE
from telegram_notifier import telegram_notifier

logger = logging.getLogger(__name__)

# IP Whitelist middleware removed - no longer needed

class AuthTokenMiddleware(BaseHTTPMiddleware):
    """Middleware to validate API authentication tokens"""
    
    def __init__(self, app, protected_paths=None):
        super().__init__(app)
        self.protected_paths = protected_paths or [
            "/add-response", 
            "/add-responses-batch", 
            "/claim-block", 
            "/update-block-status"
        ]
    
    async def dispatch(self, request: Request, call_next):
        # Only apply auth to protected API endpoints
        if request.url.path in self.protected_paths and API_AUTH_ENABLED:
            if not self._validate_token(request):
                logger.warning(f"Invalid auth token for {request.url.path}")
                return JSONResponse(
                    {"detail": "Invalid or missing authentication token"}, 
                    status_code=401
                )
        
        return await call_next(request)
    
    def _validate_token(self, request: Request) -> bool:
        """Validate authentication token"""
        if not API_AUTH_TOKEN:
            return True  # No token configured, allow access
            
        # Check Authorization header
        auth_header = request.headers.get("authorization")
        if auth_header:
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]  # Remove "Bearer " prefix
                return token == API_AUTH_TOKEN
        
        # Check X-API-Token header
        api_token = request.headers.get("x-api-token")
        if api_token:
            return api_token == API_AUTH_TOKEN
        
        # Check query parameter (for GET requests)
        query_token = request.query_params.get("token")
        if query_token:
            return query_token == API_AUTH_TOKEN
        
        return False

class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Middleware to catch and log errors, send Telegram notifications"""
    
    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
            return response
        except Exception as exc:
            # Log the error
            logger.error(f"Unhandled exception in {request.url.path}: {exc}", exc_info=True)
            
            # Send Telegram notification
            await telegram_notifier.send_error_notification(
                error=exc,
                context=f"Starlette Error - {request.method} {request.url.path}",
                additional_info={
                    "Client IP": self._get_client_ip(request),
                    "User Agent": request.headers.get("user-agent", "Unknown"),
                    "URL": str(request.url)
                }
            )
            
            # Return error response
            if request.url.path.startswith("/api/") or "application/json" in request.headers.get("accept", ""):
                return JSONResponse(
                    {"detail": "Internal server error"}, 
                    status_code=500
                )
            else:
                return HTMLResponse(
                    "<h1>Internal Server Error</h1><p>An error occurred while processing your request.</p>",
                    status_code=500
                )
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request headers"""
        x_real_ip = request.headers.get("x-real-ip")

        if x_real_ip:
            return x_real_ip
            
        x_forwarded_for = request.headers.get("x-forwarded-for")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        
        return request.client.host if request.client else "unknown"
