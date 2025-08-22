#!/bin/bash

# Script to apply database indexes for improved search performance

echo "Applying database indexes for improved search performance..."

# Copy the SQL file to the database container
docker compose cp app/create_indexes.sql db:/tmp/create_indexes.sql

# Execute the SQL script
docker compose exec -T db psql -U postgres -d webapp_stats -f /tmp/create_indexes.sql

echo "Database indexes applied successfully!"
echo "You can now restart the application for optimal performance:"
echo "docker compose restart app"
