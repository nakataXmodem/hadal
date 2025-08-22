-- Create database if it doesn't exist
-- This is handled by the POSTGRES_DB environment variable in docker-compose.yml

-- Create extensions if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
