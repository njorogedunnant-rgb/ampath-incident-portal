-- Run this in your MySQL terminal to set up the database
-- mysql -u root -p < schema.sql

CREATE DATABASE IF NOT EXISTS incident_portal;
USE incident_portal;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    email       VARCHAR(150) NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,
    department  VARCHAR(100) NOT NULL,
    role        ENUM('staff', 'admin') DEFAULT 'staff',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Incidents table
CREATE TABLE IF NOT EXISTS incidents (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    user_id        INT NOT NULL,
    incident_type  VARCHAR(100) NOT NULL,
    description    TEXT NOT NULL,
    severity       ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL,
    location       VARCHAR(150),
    status         ENUM('Open', 'In Progress', 'Resolved') DEFAULT 'Open',
    assigned_to    VARCHAR(100),
    admin_notes    TEXT,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create a default admin account
-- Password: Admin@1234 (change this immediately after first login!)
INSERT INTO users (name, email, password, department, role)
VALUES (
    'ICT Admin',
    'admin@ampath.org',
    '$2b$12$KIX8zSjvwlhfLhv3fJmJ5.eH5k5X5gZq0mHzL9RtYwN3kQvP1bO2K',
    'ICT Department',
    'admin'
) ON DUPLICATE KEY UPDATE id=id;
