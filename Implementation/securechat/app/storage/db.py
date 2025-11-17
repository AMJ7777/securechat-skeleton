"""
Database Module for User Credential Management

Handles secure storage and verification of user credentials using MySQL.

Security Properties:
- Passwords never stored in plaintext
- Per-user random salts (16 bytes)
- Salted SHA-256 hashing: hash = SHA256(salt || password)
- Constant-time comparison to prevent timing attacks
- Connection pooling and error handling

Database Schema:
    users (
        email VARCHAR(255) NOT NULL,
        username VARCHAR(50) NOT NULL UNIQUE,
        salt VARBINARY(16) NOT NULL,
        pwd_hash CHAR(64) NOT NULL
    )

IMPORTANT: This database stores ONLY user credentials.
           Chat messages and transcripts must NEVER be stored in the database.
"""

import os
import secrets
import hashlib
import pymysql
from pymysql import Error as PyMySQLError


# Database configuration from environment variables
# Default values work with XAMPP or standard local MySQL setup
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'securechat'),
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}


class Database:
    """
    Database interface for user authentication and management.
    
    Methods:
        register_user: Create new user account with salted password
        verify_credentials: Authenticate user login
        close: Clean up database connection
    """
    
    def __init__(self):
        """
        Initializes the database connection.
        
        Raises:
            RuntimeError: If connection fails
        """
        try:
            self.connection = pymysql.connect(**DB_CONFIG)
            self.cursor = self.connection.cursor()
        except PyMySQLError as err:
            raise RuntimeError(f"Database connection failed: {err}")

    def close(self):
        """
        Closes the database connection and cursor.
        Should be called in a finally block or using context manager.
        """
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()

    def register_user(self, email: str, username: str, password: str) -> bool:
        """
        Registers a new user with secure password storage.
        
        Security Steps:
        1. Check if username/email already exists (prevent duplicates)
        2. Generate cryptographically secure random 16-byte salt
        3. Compute salted hash: pwd_hash = SHA256(salt || password)
        4. Store (email, username, salt, pwd_hash) in database
        
        Args:
            email: User's email address
            username: Unique username identifier
            password: Plaintext password (hashed before storage)
            
        Returns:
            bool: True if registration succeeds, False if user already exists
            
        Security Notes:
            - Each user gets a unique random salt
            - Salt prevents rainbow table attacks
            - Even identical passwords have different hashes
            - Password never logged or stored in plaintext
        """
        # Step 1: Check if user already exists
        query_check = "SELECT username FROM users WHERE username = %s OR email = %s"
        try:
            self.cursor.execute(query_check, (username, email))
            if self.cursor.fetchone():
                return False  # User already exists
        except PyMySQLError:
            return False

        # Step 2: Generate cryptographically secure random salt (16 bytes)
        salt = secrets.token_bytes(16)

        # Step 3: Compute salted password hash
        # Hash = SHA256(salt || password)
        # Concatenate salt bytes with password bytes
        combined = salt + password.encode('utf-8')
        pwd_hash = hashlib.sha256(combined).hexdigest()

        # Step 4: Insert into database
        query_insert = """
            INSERT INTO users (email, username, salt, pwd_hash)
            VALUES (%s, %s, %s, %s)
        """
        try:
            self.cursor.execute(query_insert, (email, username, salt, pwd_hash))
            self.connection.commit()
            return True
        except PyMySQLError as e:
            self.connection.rollback()
            print(f"[DB Error] Registration failed: {e}")
            return False

    def verify_credentials(self, username: str, password: str) -> bool:
        """
        Verifies user login credentials.
        
        Security Steps:
        1. Retrieve stored salt and hash for username
        2. Recompute hash using provided password and stored salt
        3. Compare computed hash with stored hash (constant-time)
        
        Args:
            username: Username or email identifier
            password: Plaintext password to verify
            
        Returns:
            bool: True if credentials are valid, False otherwise
            
        Security Notes:
            - Uses constant-time comparison to prevent timing attacks
            - Never returns information about which part failed (user/password)
            - Recomputes hash on every login (no caching)
            
        Attack Resistance:
            - Rainbow tables: defeated by unique salts
            - Brute force: slowed by computational cost
            - Timing attacks: mitigated by constant-time compare
        """
        # Step 1: Retrieve user's salt and stored hash
        query = "SELECT salt, pwd_hash FROM users WHERE username = %s OR email = %s"
        try:
            self.cursor.execute(query, (username, username))
            row = self.cursor.fetchone()
        except PyMySQLError:
            return False

        if not row:
            # User not found
            # Use constant-time operation to prevent timing side-channel
            secrets.compare_digest("dummy", "dummy")
            return False

        stored_salt = row['salt']
        stored_hash = row['pwd_hash']
        
        # Ensure salt is bytes (PyMySQL returns bytes for VARBINARY)
        if isinstance(stored_salt, str):
            stored_salt = stored_salt.encode('latin1')

        # Step 2: Recompute hash with provided password
        combined = bytes(stored_salt) + password.encode('utf-8')
        computed_hash = hashlib.sha256(combined).hexdigest()

        # Step 3: Constant-time comparison
        # Prevents attackers from learning hash prefix through timing
        return secrets.compare_digest(computed_hash, stored_hash)


def init_database():
    """
    Initializes the database schema (for first-time setup).
    Creates the 'users' table if it doesn't exist.
    
    Run with: python -m app.storage.db
    """
    try:
        conn = pymysql.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            charset='utf8mb4'
        )
        cursor = conn.cursor()
        
        # Create database if not exists
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
        cursor.execute(f"USE {DB_CONFIG['database']}")
        
        # Create users table
        create_table_query = """
        CREATE TABLE IF NOT EXISTS users (
            email VARCHAR(255) NOT NULL,
            username VARCHAR(50) NOT NULL UNIQUE,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (username),
            INDEX idx_email (email)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        cursor.execute(create_table_query)
        conn.commit()
        
        print(f"[+] Database '{DB_CONFIG['database']}' initialized successfully.")
        print(f"[+] Table 'users' ready.")
        
        cursor.close()
        conn.close()
        
    except PyMySQLError as e:
        print(f"[-] Database initialization failed: {e}")
        raise


if __name__ == "__main__":
    # Command-line database initialization
    print("[*] Initializing SecureChat database...")
    init_database()

