#!/bin/bash

# Wait for MySQL to be fully up and running
echo "Waiting for MySQL to be ready..."
sleep 10  # Wait for MySQL to be fully initialized

# Set the root password using the mysql_native_password authentication method
echo "Changing root password and authentication method..."
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$MYSQL_ROOT_PASSWORD';"
mysql -u root -e "FLUSH PRIVILEGES;"

# Optionally, you can create a new database or user if needed:
# mysql -u root -e "CREATE DATABASE my_database;"

# Now MySQL is ready, run the init-db.sql script
echo "Running init-db.sql script..."
mysql -u root -p"$MYSQL_ROOT_PASSWORD" < /docker-entrypoint-initdb.d/init-db.sql

# Finish setup
echo "MySQL setup complete!"


