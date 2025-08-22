

-- Indexes for host_responses table
CREATE INDEX idx_host_responses_ip ON host_responses (ip_address);
CREATE INDEX idx_host_responses_port ON host_responses (port);
CREATE INDEX idx_host_responses_scan_time ON host_responses (scan_timestamp);
-- A composite index for your most common web app queries:
CREATE INDEX idx_search ON host_responses (port, is_active, scan_timestamp);

-- Additional useful indexes for network_blocks table
CREATE INDEX idx_network_blocks_status ON network_blocks (status);
CREATE INDEX idx_network_blocks_assigned ON network_blocks (assigned_to);
CREATE INDEX idx_network_blocks_created ON network_blocks (created_at);


-- Database indexes for improved search performance

-- Run this script to add indexes to existing tables

-- Network blocks indexes
CREATE INDEX IF NOT EXISTS idx_network_blocks_status ON network_blocks(status);
CREATE INDEX IF NOT EXISTS idx_network_blocks_created_at ON network_blocks(created_at);
CREATE INDEX IF NOT EXISTS idx_network_blocks_status_created ON network_blocks(status, created_at);

-- Host responses indexes
CREATE INDEX IF NOT EXISTS idx_host_responses_ip_port ON host_responses(ip_address, port);
CREATE INDEX IF NOT EXISTS idx_host_responses_scan_timestamp ON host_responses(scan_timestamp);
CREATE INDEX IF NOT EXISTS idx_host_responses_created_at ON host_responses(created_at);
CREATE INDEX IF NOT EXISTS idx_host_responses_is_active ON host_responses(is_active);
CREATE INDEX IF NOT EXISTS idx_host_responses_status_code ON host_responses(status_code);
CREATE INDEX IF NOT EXISTS idx_host_responses_protocol ON host_responses(protocol);
CREATE INDEX IF NOT EXISTS idx_host_responses_title ON host_responses(title);
CREATE INDEX IF NOT EXISTS idx_host_responses_banner ON host_responses(banner);
CREATE INDEX IF NOT EXISTS idx_host_responses_headers ON host_responses(headers);
CREATE INDEX IF NOT EXISTS idx_host_responses_http_response ON host_responses(http_response);
CREATE INDEX IF NOT EXISTS idx_host_responses_certificate ON host_responses(certificate);

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_host_responses_active_timestamp ON host_responses(is_active, scan_timestamp);
CREATE INDEX IF NOT EXISTS idx_host_responses_ip_timestamp ON host_responses(ip_address, scan_timestamp);
CREATE INDEX IF NOT EXISTS idx_host_responses_port_timestamp ON host_responses(port, scan_timestamp);
CREATE INDEX IF NOT EXISTS idx_host_responses_status_timestamp ON host_responses(status_code, scan_timestamp);

-- Text search indexes for ILIKE queries (PostgreSQL specific)
CREATE INDEX IF NOT EXISTS idx_host_responses_ip_text ON host_responses USING gin(to_tsvector('english', ip_address::text));
CREATE INDEX IF NOT EXISTS idx_host_responses_banner_text ON host_responses USING gin(to_tsvector('english', banner));
CREATE INDEX IF NOT EXISTS idx_host_responses_headers_text ON host_responses USING gin(to_tsvector('english', headers));
CREATE INDEX IF NOT EXISTS idx_host_responses_http_response_text ON host_responses USING gin(to_tsvector('english', http_response));
CREATE INDEX IF NOT EXISTS idx_host_responses_certificate_text ON host_responses USING gin(to_tsvector('english', certificate));
CREATE INDEX IF NOT EXISTS idx_host_responses_title_text ON host_responses USING gin(to_tsvector('english', title));

-- Analyze tables to update statistics
ANALYZE network_blocks;
ANALYZE host_responses;
