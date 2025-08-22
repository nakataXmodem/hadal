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
