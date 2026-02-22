sudo apt install mysql-server -y
sudo systemctl start mysql
sudo systemctl enable mysql
sudo systemctl status mysql
sudo mysql_secure_installation

sudo mysql

ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'your_password';
FLUSH PRIVILEGES;




CREATE DATABASE IF NOT EXISTS slickproxy;

USE slickproxy;

CREATE TABLE IF NOT EXISTS users( 
  user VARCHAR(32) NOT NULL DEFAULT '',
  password VARCHAR(35) NOT NULL DEFAULT '',
  proxyIP VARCHAR(45),
  proxyIPList LONGTEXT,
  proxyPort LONGTEXT,
  activeConnections INT,
  connectionsPerSecond INT,
  throughputPerSecond INT,
  totalQuota INT,
  quotaDuration VARCHAR(10),
  timeQuota INT,
  ipMode VARCHAR(20),
  ipRotation VARCHAR(20),
  portToIP LONGTEXT,
  whiteListIP LONGTEXT,
  rotationIntervalSec INT,
  bytesPerSecond BIGINT UNSIGNED DEFAULT 0,
  currentActiveConnections BIGINT UNSIGNED DEFAULT 0,
  totalUsedBytes BIGINT UNSIGNED DEFAULT 0,
  PRIMARY KEY (user)
);

CREATE TABLE blacklist (
    value VARCHAR(255) NOT NULL,
    type VARCHAR(255) NOT NULL,
    PRIMARY KEY (value, type)
);


-- Create the listenports table
CREATE TABLE listenports (
    port INT NOT NULL UNIQUE
);

-- Insert some sample ports
INSERT INTO listenports (port) VALUES (4567);

