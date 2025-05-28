#!/usr/bin/env python3
"""
main server for the WALA
"""

import sys
import threading
import time
import logging
import signal
import socket
from datetime import datetime, timedelta

import config
import protocol
import database
import crypto_utils


class WALAServer:
    """Main WALA server class"""
    
    def __init__(self, host=config.DEFAULT_SERVER_HOST, port=config.DEFAULT_SERVER_PORT):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None
        self.clients = {}
        self.client_threads = {}
        self.db = database.Database()
        
        logging.basicConfig(
            level=logging.INFO,
            format=config.LOG_FORMAT,
            datefmt=config.LOG_DATE_FORMAT
        )
        self.logger = logging.getLogger('WALAServer')
        
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.logger.info("WALA Server initializing...")
        self.logger.info(f"Server configuration: {host}:{port}")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.shutdown()
    
    def start(self):
        """Start the server"""
        try:
            self.server_socket = protocol.create_server_socket(self.host, self.port)
            self.server_socket.listen(config.MAX_CONNECTIONS)
            
            self.running = True
            self.logger.info(f"WALA Server started on {self.host}:{self.port}")
            self.logger.info("Waiting for client connections...")
            
            admin_thread = threading.Thread(target=self.admin_console, daemon=True)
            admin_thread.start()
            
            # Start key rotation scheduler
            rotation_thread = threading.Thread(target=self.key_rotation_scheduler, daemon=True)
            rotation_thread.start()
            self.logger.info("Key rotation scheduler started")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.logger.info(f"NEW CONNECTION from {client_address[0]}:{client_address[1]}")
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        self.logger.error(f"Socket error: {e}")
                    break
                except Exception as e:
                    self.logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            sys.exit(1)
    
    def key_rotation_scheduler(self):
        """Background thread to check and initiate key rotation"""
        while self.running:
            try:
                time.sleep(config.KEY_ROTATION_CHECK_INTERVAL)
                
                if not self.running:
                    break
                
                self.check_key_rotation()
                
            except Exception as e:
                self.logger.error(f"Error in key rotation scheduler: {e}")
    
    def check_key_rotation(self):
        """Check which users need key rotation and send rotation requests"""
        try:
            users_to_rotate = self.db.get_users_for_key_rotation()
            
            if users_to_rotate:
                self.logger.info(f"Initiating key rotation for {len(users_to_rotate)} users")
                
                for username in users_to_rotate:
                    if username in self.clients and not self.clients[username].is_closed():
                        self.request_key_rotation(username)
                
                self.db.log_event('KEY_ROTATION', None, 
                                f'Key rotation initiated for {len(users_to_rotate)} users')
            
        except Exception as e:
            self.logger.error(f"Error checking key rotation: {e}")
    
    def request_key_rotation(self, username):
        """Send key rotation request to a specific user"""
        try:
            if username in self.clients:
                message = protocol.create_key_rotation_request_message()
                self.clients[username].send(message)
                self.logger.info(f"Sent key rotation request to {username}")
        except Exception as e:
            self.logger.error(f"Error sending key rotation request to {username}: {e}")
    
    def handle_client(self, client_socket, client_address):
        """Handle a client connection"""
        connection = protocol.SecureConnection(client_socket)
        username = None
        
        try:
            username = self.authenticate_client(connection, client_address)
            if not username:
                return
            
            self.logger.info(f"Authentication successful for user '{username}'")
            
            self.clients[username] = connection
            self.client_threads[username] = threading.current_thread()
            
            self.db.set_user_online(username, True)
            
            # Check if this user needs key rotation
            users_needing_rotation = self.db.get_users_for_key_rotation()
            if username in users_needing_rotation:
                self.request_key_rotation(username)
            
            self.deliver_pending_messages(username)
            
            while self.running and not connection.is_closed():
                try:
                    message = connection.receive()
                    if not message:
                        break
                    
                    self.handle_message(username, message)
                    
                except protocol.ProtocolError as e:
                    self.logger.warning(f"Protocol error from '{username}': {e}")
                    break
                except Exception as e:
                    self.logger.error(f"Error handling message from '{username}': {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"Error handling client {client_address}: {e}")
        finally:
            if username:
                self.cleanup_client(username)
    
    def authenticate_client(self, connection, client_address):
        """Authenticate a client connection"""
        try:
            message = connection.receive()
            if not message:
                return None
            
            if message.type == config.MSG_TYPE_LOGIN:
                username = message.data.get('username')
                password = message.data.get('password')
                
                if not username or not password:
                    connection.send(protocol.create_error_message(
                        config.ERROR_INVALID_CREDENTIALS, "Missing username or password"
                    ))
                    return None
                
                if self.db.authenticate_user(username, password):
                    if username in self.clients:
                        connection.send(protocol.create_error_message(
                            config.ERROR_INVALID_CREDENTIALS, "User already connected"
                        ))
                        return None
                    
                    connection.send(protocol.create_success_message("Login successful"))
                    self.logger.info(f"LOGIN SUCCESSFUL for '{username}'")
                    return username
                else:
                    connection.send(protocol.create_error_message(
                        config.ERROR_INVALID_CREDENTIALS, "Invalid username or password"
                    ))
                    return None
                    
            elif message.type == config.MSG_TYPE_REGISTER:
                username = message.data.get('username')
                password = message.data.get('password')
                
                if not username or not password:
                    connection.send(protocol.create_error_message(
                        config.ERROR_INVALID_CREDENTIALS, "Missing username or password"
                    ))
                    return None
                
                if len(password) < config.PASSWORD_MIN_LENGTH:
                    connection.send(protocol.create_error_message(
                        config.ERROR_INVALID_CREDENTIALS, 
                        f"Password must be at least {config.PASSWORD_MIN_LENGTH} characters"
                    ))
                    return None
                
                if self.db.register_user(username, password):
                    connection.send(protocol.create_success_message("Registration successful"))
                    self.logger.info(f"REGISTRATION SUCCESSFUL for '{username}'")
                    return username
                else:
                    connection.send(protocol.create_error_message(
                        config.ERROR_INVALID_CREDENTIALS, "Username already exists"
                    ))
                    return None
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"Authentication error for {client_address}: {e}")
            return None
    
    def handle_message(self, username, message):
        """Handle a message from a client"""
        try:
            if message.type == config.MSG_TYPE_PUBLIC_KEY:
                public_key_pem = message.data.get('public_key')
                if public_key_pem:
                    self.db.store_public_key(username, public_key_pem.encode('utf-8'))
                    self.logger.info(f"STORED PUBLIC KEY for user '{username}'")
                    
            elif message.type == config.MSG_TYPE_KEY_REQUEST:
                target_username = message.data.get('target_username')
                
                if target_username and self.db.user_exists(target_username):
                    public_key_pem = self.db.get_public_key(target_username)
                    if public_key_pem:
                        response = protocol.create_key_response_message(
                            target_username, public_key_pem.decode('utf-8')
                        )
                        self.clients[username].send(response)
                        self.logger.info(f"SENT PUBLIC KEY for '{target_username}' to '{username}'")
                    else:
                        self.clients[username].send(protocol.create_error_message(
                            config.ERROR_USER_NOT_FOUND, "User has no public key"
                        ))
                else:
                    self.clients[username].send(protocol.create_error_message(
                        config.ERROR_USER_NOT_FOUND, "User not found"
                    ))
                    
            elif message.type == config.MSG_TYPE_SESSION_KEY:
                self.route_message(username, message)
                
            elif message.type == config.MSG_TYPE_CHAT_MESSAGE:
                self.route_message(username, message)
                
            elif message.type == config.MSG_TYPE_USER_LIST:
                online_users = self.db.get_online_users()
                if username in online_users:
                    online_users.remove(username)
                response = protocol.create_user_list_message(online_users)
                self.clients[username].send(response)
                
            elif message.type == config.MSG_TYPE_LOGOUT:
                self.logger.info(f"LOGOUT: User '{username}' logging out")
                self.clients[username].close()
                
        except Exception as e:
            self.logger.error(f"Error handling message from '{username}': {e}")
    
    def log_encryption_details(self, sender, recipient, message):
        """Log detailed encryption information for demonstration purposes"""
        self.logger.info("="*70)
        self.logger.info("ENCRYPTED MESSAGE TRANSFER DETECTED")
        self.logger.info("="*70)
        
        if message.type == config.MSG_TYPE_SESSION_KEY:
            self.logger.info(f"MESSAGE TYPE: SESSION KEY EXCHANGE")
            self.logger.info(f"FROM: {sender} → TO: {recipient}")
            self.logger.info("ENCRYPTION TECHNIQUES USED:")
            self.logger.info("  • RSA-OAEP (2048-bit) - Encrypting DES session key")
            self.logger.info("  • RSA-PSS Digital Signature - Authenticating sender")
            
            encrypted_key = message.data.get('encrypted_session_key', '')
            if encrypted_key:
                # Show first 64 characters of encrypted session key
                preview = encrypted_key[:64] + "..." if len(encrypted_key) > 64 else encrypted_key
                self.logger.info(f"ENCRYPTED SESSION KEY (preview): {preview}")
            
            signature = message.data.get('signature', '')
            if signature:
                # Show first 32 characters of signature
                sig_preview = signature[:32] + "..." if len(signature) > 32 else signature
                self.logger.info(f"DIGITAL SIGNATURE (preview): {sig_preview}")
        
        elif message.type == config.MSG_TYPE_CHAT_MESSAGE:
            self.logger.info(f"MESSAGE TYPE: ENCRYPTED CHAT MESSAGE")
            self.logger.info(f"FROM: {sender} → TO: {recipient}")
            self.logger.info("ENCRYPTION TECHNIQUES USED:")
            self.logger.info("  • DES-CBC (64-bit) - Encrypting message content")
            self.logger.info("  • RSA-PSS Digital Signature - Message integrity & authentication")
            
            encrypted_content = message.data.get('encrypted_content', '')
            if encrypted_content:
                # Show first 96 characters of encrypted content
                preview = encrypted_content[:96] + "..." if len(encrypted_content) > 96 else encrypted_content
                self.logger.info(f"ENCRYPTED MESSAGE CONTENT (preview): {preview}")
            
            signature = message.data.get('signature', '')
            if signature:
                # Show first 32 characters of signature
                sig_preview = signature[:32] + "..." if len(signature) > 32 else signature
                self.logger.info(f"DIGITAL SIGNATURE (preview): {sig_preview}")
        
        self.logger.info("="*70)
    
    def route_message(self, sender, message):
        """Route a message to its recipient"""
        try:
            recipient = message.recipient
            
            if not recipient:
                return
            
            if not self.db.user_exists(recipient):
                self.clients[sender].send(protocol.create_error_message(
                    config.ERROR_USER_NOT_FOUND, f"User {recipient} not found"
                ))
                return
            
            # Log encryption details for demonstration
            self.log_encryption_details(sender, recipient, message)
            
            if message.type == config.MSG_TYPE_CHAT_MESSAGE:
                encrypted_content = crypto_utils.decode_base64(message.data.get('encrypted_content', ''))
                signature = crypto_utils.decode_base64(message.data.get('signature', ''))
                self.db.store_message(sender, recipient, encrypted_content, signature)
            
            if recipient in self.clients and not self.clients[recipient].is_closed():
                try:
                    self.clients[recipient].send(message)
                    self.logger.info(f"✓ MESSAGE DELIVERED: '{sender}' → '{recipient}'")
                    
                except Exception as e:
                    self.logger.error(f"Failed to deliver message to '{recipient}': {e}")
            else:
                if message.type == config.MSG_TYPE_CHAT_MESSAGE:
                    self.logger.info(f"MESSAGE STORED: '{sender}' → '{recipient}' (recipient offline)")
                    self.clients[sender].send(protocol.create_error_message(
                        config.ERROR_USER_OFFLINE, f"User {recipient} is offline, message stored"
                    ))
                
        except Exception as e:
            self.logger.error(f"Error routing message from '{sender}': {e}")
    
    def deliver_pending_messages(self, username):
        """Deliver pending messages to a user who just came online"""
        try:
            messages = self.db.get_undelivered_messages(username)
            
            if messages:
                current_time = datetime.now()
                session_cutoff = current_time - timedelta(hours=2)
                
                for msg_id, sender, encrypted_content, signature, timestamp in messages:
                    try:
                        msg_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                        if msg_time >= session_cutoff:
                            message = protocol.create_chat_message(
                                sender, username,
                                crypto_utils.encode_base64(encrypted_content),
                                crypto_utils.encode_base64(signature)
                            )
                            
                            self.clients[username].send(message)
                            self.db.mark_message_delivered(msg_id)
                            self.logger.info(f"Delivered pending message {msg_id} to '{username}'")
                        else:
                            self.db.mark_message_delivered(msg_id)
                    except Exception as e:
                        self.logger.error(f"Failed to deliver pending message {msg_id}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error delivering pending messages to '{username}': {e}")
    
    def cleanup_client(self, username):
        """Clean up a disconnected client"""
        try:
            self.db.set_user_online(username, False)
            
            if username in self.clients:
                self.clients[username].close()
                del self.clients[username]
            
            if username in self.client_threads:
                del self.client_threads[username]
            
            self.logger.info(f"User '{username}' disconnected")
            
        except Exception as e:
            self.logger.error(f"Error cleaning up client '{username}': {e}")
    
    def admin_console(self):
        """Admin console for server management"""
        self.logger.info("Admin console started. Type 'help' for commands.")
        
        while self.running:
            try:
                command = input().strip().lower()
                
                if command == 'help':
                    print("\nAdmin Commands:")
                    print("  listusers  - List connected users")
                    print("  stats      - Show server statistics")
                    print("  logs       - Show recent system logs")
                    print("  quit       - Shutdown server")
                    print("  help       - Show this help")
                    
                elif command == 'listusers':
                    online_users = list(self.clients.keys())
                    print(f"\nOnline users ({len(online_users)}):")
                    for user in online_users:
                        print(f"  - {user}")
                    
                elif command == 'stats':
                    stats = self.db.get_user_stats()
                    print(f"\nServer Statistics:")
                    print(f"  Total users: {stats['total_users']}")
                    print(f"  Online users: {stats['online_users']}")
                    print(f"  Total messages: {stats['total_messages']}")
                    print(f"  Undelivered messages: {stats['undelivered_messages']}")
                    print(f"  Active connections: {len(self.clients)}")
                    
                elif command == 'logs':
                    logs = self.db.get_system_logs(20)
                    print(f"\nRecent System Logs:")
                    for event_type, username, description, timestamp in logs:
                        user_str = f"[{username}]" if username else "[SYSTEM]"
                        print(f"  {timestamp} {user_str} {event_type}: {description}")
                    
                elif command == 'quit':
                    self.shutdown()
                    break
                    
                elif command == '':
                    continue
                    
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")
                    
            except EOFError:
                break
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Admin console error: {e}")
    
    def shutdown(self):
        """Shutdown the server gracefully"""
        if not self.running:
            return
            
        self.logger.info("SHUTDOWN INITIATED...")
        self.running = False
        
        active_clients = list(self.clients.items())
        
        for username, connection in active_clients:
            try:
                connection.close()
                self.db.set_user_online(username, False)
            except Exception:
                pass
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        
        self.db.close()
        
        self.logger.info("Server shutdown complete")


def main():
    """Main function"""
    host = config.DEFAULT_SERVER_HOST
    port = config.DEFAULT_SERVER_PORT
    
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    
    if len(sys.argv) > 2:
        host = sys.argv[2]
    
    server = WALAServer(host, port)
    server.start()


if __name__ == "__main__":
    main()