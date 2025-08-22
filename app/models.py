from sqlalchemy import Column, Integer, Float, DateTime, Text, String, Boolean, BigInteger, Index
from sqlalchemy.dialects.postgresql import CIDR, INET, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()

class NetworkBlock(Base):
    __tablename__ = "network_blocks"
    
    id = Column(BigInteger, primary_key=True, index=True)
    network = Column(CIDR, nullable=False)
    status = Column(String(20), nullable=False)  # PENDING, IN_PROGRESS, COMPLETED, FAILED
    assigned_to = Column(String(255), nullable=True)
    last_assigned = Column(TIMESTAMP, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    
    # Indexes for better performance
    __table_args__ = (
        Index('idx_network_blocks_status', 'status'),
        Index('idx_network_blocks_created_at', 'created_at'),
        Index('idx_network_blocks_status_created', 'status', 'created_at'),
    )
    
    def __repr__(self):
        return f"<NetworkBlock(id={self.id}, network={self.network}, status={self.status})>"

class HostResponse(Base):
    __tablename__ = "host_responses"
    
    id = Column(BigInteger, primary_key=True, index=True)
    ip_address = Column(INET, nullable=False)
    port = Column(Integer, nullable=False)
    is_active = Column(Boolean, nullable=False)
    protocol = Column(String(10), nullable=False, default='tcp')
    # Limit potentially large text fields to prevent oversized rows
    banner = Column(String(512), nullable=True)
    http_response = Column(String(8192), nullable=True)
    headers = Column(String(4096), nullable=True)
    certificate = Column(String(8192), nullable=True)
    title = Column(String(512), nullable=True)
    icon_hash = Column(String(32), nullable=True)
    scan_timestamp = Column(TIMESTAMP, nullable=False, server_default=func.now())
    created_at = Column(TIMESTAMP, server_default=func.now())
    # HTTP status/response code
    status_code = Column(Integer, nullable=True)
    
    # Indexes for better search performance
    __table_args__ = (
        Index('idx_host_responses_ip_port', 'ip_address', 'port'),
        Index('idx_host_responses_scan_timestamp', 'scan_timestamp'),
        Index('idx_host_responses_created_at', 'created_at'),
        Index('idx_host_responses_is_active', 'is_active'),
        Index('idx_host_responses_status_code', 'status_code'),
        Index('idx_host_responses_protocol', 'protocol'),
        Index('idx_host_responses_title', 'title'),
        Index('idx_host_responses_banner', 'banner'),
        Index('idx_host_responses_headers', 'headers'),
        Index('idx_host_responses_http_response', 'http_response'),
        Index('idx_host_responses_certificate', 'certificate'),
        # Composite indexes for common query patterns
        Index('idx_host_responses_active_timestamp', 'is_active', 'scan_timestamp'),
        Index('idx_host_responses_ip_timestamp', 'ip_address', 'scan_timestamp'),
        Index('idx_host_responses_port_timestamp', 'port', 'scan_timestamp'),
        Index('idx_host_responses_status_timestamp', 'status_code', 'scan_timestamp'),
    )
    
    def __repr__(self):
        return f"<HostResponse(id={self.id}, ip={self.ip_address}, port={self.port}, active={self.is_active})>"
