"""
all database operations for the WALA application:
"""

import sqlite3
import threading
import datetime
import config
import crypto_utils


class DatabaseError(Exception):
    pass


class Database:
    
    def __init__(self, db_file=config.DATABASE_FILE):
        self.db_file = db_file
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_file)
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password_hash BLOB NOT NULL,
                        public_key BLOB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        is_online BOOLEAN DEFAULT 0,
                        key_generated_at TIMESTAMP
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender TEXT NOT NULL,
                        recipient TEXT NOT NULL,
                        encrypted_content BLOB NOT NULL,
                        signature BLOB NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        delivered BOOLEAN DEFAULT 0,
                        FOREIGN KEY (sender) REFERENCES users (username),
                        FOREIGN KEY (recipient) REFERENCES users (username)
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS session_keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user1 TEXT NOT NULL,
                        user2 TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(user1, user2),
                        FOREIGN KEY (user1) REFERENCES users (username),
                        FOREIGN KEY (user2) REFERENCES users (username)
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS system_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        username TEXT,
                        description TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Add key_generated_at column if it doesn't exist
                cursor.execute("PRAGMA table_info(users)")
                columns = [column[1] for column in cursor.fetchall()]
                if 'key_generated_at' not in columns:
                    cursor.execute('ALTER TABLE users ADD COLUMN key_generated_at TIMESTAMP')
                
                conn.commit()
                conn.close()
                
            except Exception as e:
                raise DatabaseError(f"Failed to initialize database: {e}")
    
    def get_connection(self):
        return sqlite3.connect(self.db_file)
    
    def register_user(self, username, password):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
                if cursor.fetchone():
                    conn.close()
                    return False
                
                password_hash = crypto_utils.hash_password(password)
                
                cursor.execute('''
                    INSERT INTO users (username, password_hash)
                    VALUES (?, ?)
                ''', (username, password_hash))
                
                conn.commit()
                conn.close()
                
                self.log_event('USER_REGISTER', username, f'User {username} registered')
                
                return True
                
            except Exception as e:
                raise DatabaseError(f"Failed to register user: {e}")
    
    def authenticate_user(self, username, password):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
                result = cursor.fetchone()
                
                if not result:
                    conn.close()
                    return False
                
                password_hash = result[0]
                
                is_valid = crypto_utils.verify_password(password, password_hash)
                
                if is_valid:
                    cursor.execute('''
                        UPDATE users SET last_login = CURRENT_TIMESTAMP
                        WHERE username = ?
                    ''', (username,))
                    conn.commit()
                    
                    self.log_event('USER_LOGIN', username, f'User {username} logged in')
                
                conn.close()
                return is_valid
                
            except Exception as e:
                raise DatabaseError(f"Failed to authenticate user: {e}")
    
    def set_user_online(self, username, online=True):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE users SET is_online = ?
                    WHERE username = ?
                ''', (online, username))
                
                conn.commit()
                conn.close()
                
                status = 'online' if online else 'offline'
                self.log_event('USER_STATUS', username, f'User {username} went {status}')
                
            except Exception as e:
                raise DatabaseError(f"Failed to set user status: {e}")
    
    def store_public_key(self, username, public_key_pem):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE users SET public_key = ?, key_generated_at = CURRENT_TIMESTAMP
                    WHERE username = ?
                ''', (public_key_pem, username))
                
                conn.commit()
                conn.close()
                
                self.log_event('KEY_UPDATE', username, f'Public key updated for {username}')
                
            except Exception as e:
                raise DatabaseError(f"Failed to store public key: {e}")
    
    def get_public_key(self, username):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('SELECT public_key FROM users WHERE username = ?', (username,))
                result = cursor.fetchone()
                
                conn.close()
                
                return result[0] if result else None
                
            except Exception as e:
                raise DatabaseError(f"Failed to get public key: {e}")
    
    def get_users_for_key_rotation(self):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT username 
                    FROM users 
                    WHERE is_online = 1 
                    AND key_generated_at IS NOT NULL
                    AND (julianday('now') - julianday(key_generated_at)) * 86400 > ?
                ''', (config.KEY_ROTATION_INTERVAL,))
                
                users = [row[0] for row in cursor.fetchall()]
                
                conn.close()
                return users
                
            except Exception as e:
                raise DatabaseError(f"Failed to get users for key rotation: {e}")
    
    def store_message(self, sender, recipient, encrypted_content, signature):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO messages (sender, recipient, encrypted_content, signature)
                    VALUES (?, ?, ?, ?)
                ''', (sender, recipient, encrypted_content, signature))
                
                message_id = cursor.lastrowid
                conn.commit()
                conn.close()
                
                self.log_event('MESSAGE_STORE', sender, 
                             f'Message from {sender} to {recipient} stored (ID: {message_id})')
                
                return message_id
                
            except Exception as e:
                raise DatabaseError(f"Failed to store message: {e}")
    
    def get_undelivered_messages(self, username):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT id, sender, encrypted_content, signature, timestamp
                    FROM messages
                    WHERE recipient = ? AND delivered = 0
                    ORDER BY timestamp ASC
                ''', (username,))
                
                messages = cursor.fetchall()
                conn.close()
                
                return messages
                
            except Exception as e:
                raise DatabaseError(f"Failed to get undelivered messages: {e}")
    
    def mark_message_delivered(self, message_id):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE messages SET delivered = 1
                    WHERE id = ?
                ''', (message_id,))
                
                conn.commit()
                conn.close()
                
            except Exception as e:
                raise DatabaseError(f"Failed to mark message as delivered: {e}")
    
    def get_online_users(self):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('SELECT username FROM users WHERE is_online = 1')
                users = [row[0] for row in cursor.fetchall()]
                
                conn.close()
                return users
                
            except Exception as e:
                raise DatabaseError(f"Failed to get online users: {e}")
    
    def user_exists(self, username):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
                exists = cursor.fetchone() is not None
                
                conn.close()
                return exists
                
            except Exception as e:
                raise DatabaseError(f"Failed to check if user exists: {e}")
    
    def is_user_online(self, username):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('SELECT is_online FROM users WHERE username = ?', (username,))
                result = cursor.fetchone()
                
                conn.close()
                return bool(result[0]) if result else False
                
            except Exception as e:
                raise DatabaseError(f"Failed to check user online status: {e}")
    
    def log_event(self, event_type, username=None, description=None):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO system_logs (event_type, username, description)
                VALUES (?, ?, ?)
            ''', (event_type, username, description))
            
            conn.commit()
            conn.close()
            
        except Exception:
            pass
    
    def get_system_logs(self, limit=100):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT event_type, username, description, timestamp
                    FROM system_logs
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (limit,))
                
                logs = cursor.fetchall()
                conn.close()
                
                return logs
                
            except Exception as e:
                raise DatabaseError(f"Failed to get system logs: {e}")
    
    def get_user_stats(self):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                cursor.execute('SELECT COUNT(*) FROM users')
                total_users = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM users WHERE is_online = 1')
                online_users = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM messages')
                total_messages = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM messages WHERE delivered = 0')
                undelivered_messages = cursor.fetchone()[0]
                
                conn.close()
                
                return {
                    'total_users': total_users,
                    'online_users': online_users,
                    'total_messages': total_messages,
                    'undelivered_messages': undelivered_messages
                }
                
            except Exception as e:
                raise DatabaseError(f"Failed to get user stats: {e}")
    
    def cleanup_offline_users(self):
        with self.lock:
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                
                self.log_event('CLEANUP', None, 'Offline user cleanup performed')
                
                conn.close()
                
            except Exception as e:
                raise DatabaseError(f"Failed to cleanup offline users: {e}")
    
    def close(self):
        pass