-- Path: init.sql
CREATE DATABASE IF NOT EXISTS `fastapi`;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(50) NOT NULL,
    description VARCHAR(255) NOT NULL,
    owner_id INT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- insert first user
INSERT INTO users (`username`, password, disabled) VALUES ('admin', 'admin', 0);