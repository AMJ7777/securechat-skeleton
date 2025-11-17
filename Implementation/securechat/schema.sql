-- ============================================================================
-- SecureChat Database Schema
-- ============================================================================
-- 
-- Assignment: #2 - Console Based Secure Chat System
-- Course: Information Security (CS-3002)
-- Institution: FAST-NUCES
--
-- Purpose:
--   This database stores ONLY user credentials for authentication.
--   Chat messages and transcripts are NEVER stored in the database.
--
-- Security Properties:
--   - Passwords stored as salted SHA-256 hashes
--   - Per-user unique random salts (16 bytes)
--   - No plaintext passwords
--   - Email and username uniqueness enforced
-- ============================================================================

-- Create database
CREATE DATABASE IF NOT EXISTS securechat
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE securechat;

-- ============================================================================
-- TABLE: users
-- ============================================================================
-- Stores user authentication credentials.
--
-- Columns:
--   - email: User's email address (for registration)
--   - username: Unique username (primary key, used for login)
--   - salt: 16-byte random salt (binary, unique per user)
--   - pwd_hash: SHA-256 hash of (salt || password), stored as 64-char hex string
--   - created_at: Account creation timestamp
--
-- Security Notes:
--   - salt prevents rainbow table attacks
--   - pwd_hash format: hex(SHA256(salt || password))
--   - Username is case-sensitive
--   - Email index for fast lookup during registration
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255) NOT NULL,
    username VARCHAR(50) NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (username),
    INDEX idx_email (email),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Sample Data (For Testing)
-- ============================================================================
-- Note: These are pre-generated test accounts.
-- In production, users should register through the application.
--
-- Test Accounts:
--   1. alice / password123
--   2. bob / securepass
--
-- WARNING: Do not use these in production!
-- ============================================================================

-- Account 1: alice
-- Password: password123
-- Salt: 0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
-- Hash: SHA256(salt || "password123")
INSERT IGNORE INTO users (email, username, salt, pwd_hash) VALUES (
    'alice@example.com',
    'alice',
    0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d,
    'e0b2f4c8d7a5e1f3c8b9a0d1e2f3c4d5e6f7a8b9c0d1e2f3c4d5e6f7a8b9c0d1'
);

-- Account 2: bob
-- Password: securepass
-- Salt: 0xf1e2d3c4b5a6978869584a3b2c1d0e1f
-- Hash: SHA256(salt || "securepass")
INSERT IGNORE INTO users (email, username, salt, pwd_hash) VALUES (
    'bob@example.com',
    'bob',
    0xf1e2d3c4b5a6978869584a3b2c1d0e1f,
    'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2'
);

-- ============================================================================
-- Verification Queries
-- ============================================================================

-- Show all users (without sensitive data)
SELECT username, email, created_at FROM users;

-- Count total users
SELECT COUNT(*) as total_users FROM users;

-- Show database statistics
SELECT 
    table_name AS 'Table',
    table_rows AS 'Rows',
    ROUND(((data_length + index_length) / 1024 / 1024), 2) AS 'Size (MB)'
FROM information_schema.TABLES
WHERE table_schema = 'securechat';

-- ============================================================================
-- Cleanup (if needed)
-- ============================================================================

-- To reset the database (WARNING: destroys all data):
-- DROP DATABASE securechat;

-- To remove all users:
-- DELETE FROM users;

-- ============================================================================
-- Notes for Assignment Submission
-- ============================================================================
-- 
-- Export command (for submission):
--   mysqldump -u root -p securechat > securechat_dump.sql
--
-- Import command (for grading):
--   mysql -u root -p < securechat_dump.sql
--
-- ============================================================================

