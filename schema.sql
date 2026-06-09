-- PostgreSQL schema for AMPATH Incident Portal
-- Run this in your Render PostgreSQL console

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    email       VARCHAR(150) NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,
    department  VARCHAR(100) NOT NULL,
    role        VARCHAR(20) NOT NULL DEFAULT 'staff' CHECK (role IN ('staff', 'admin', 'technician')),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Incidents table
CREATE TABLE IF NOT EXISTS incidents (
    id              SERIAL PRIMARY KEY,
    user_id         INT NOT NULL,
    incident_type   VARCHAR(100) NOT NULL,
    description     TEXT NOT NULL,
    severity        VARCHAR(10) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    location        VARCHAR(150),
    status          VARCHAR(15) NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'In Progress', 'Resolved')),
    urgency         VARCHAR(10) DEFAULT 'Low',
    impact          VARCHAR(10) DEFAULT 'Low',
    priority        VARCHAR(5) DEFAULT 'P5',
    assigned_to     VARCHAR(100),
    admin_notes     TEXT,
    photo           TEXT,
    feedback_rating INT,
    feedback_comment TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Auto-update updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Knowledge Base table
CREATE TABLE IF NOT EXISTS knowledge_base (
    id            SERIAL PRIMARY KEY,
    title         VARCHAR(200) NOT NULL,
    incident_type VARCHAR(100) NOT NULL,
    problem       TEXT NOT NULL,
    solution      TEXT NOT NULL,
    created_by    VARCHAR(100),
    incident_id   INT,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Default admin account
-- Password: Admin@1234 (change after first login!)
INSERT INTO users (name, email, password, department, role)
VALUES (
    'ICT Admin',
    'admin@ampath.org',
    '$2b$12$KIX8zSjvwlhfLhv3fJmJ5.eH5k5X5gZq0mHzL9RtYwN3kQvP1bO2K',
    'ICT Department',
    'admin'
) ON CONFLICT (email) DO NOTHING;
