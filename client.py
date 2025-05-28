#!/usr/bin/env python3
"""
client application for the WALA chat system.
"""

import sys
import threading
import time
import getpass
import signal
from datetime import datetime

import config
import protocol
import crypto_utils


class WALAClient:
    
    def __init__(self, server_host=config.DEFAULT_SERVER_HOST, server_port=config.DEFAULT_SERVER_PORT):
        self.server_host = server_host
        self.server_port = server_port
        self.connection = None
        self.username = None
        self.running = False
        
        self.private_key = None
        self.public_key = None
        
        self.session_keys = {}
        
        self.public_keys = {}
        
        self.pending_messages = {}
        
        self.pending_session_keys = {}
        
        self.key_establishment_locks = {}
        
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        self.shutdown()
    
    def connect_to_server(self):
        try:
            sock = protocol.create_client_socket(self.server_host, self.server_port)
            self.connection = protocol.SecureConnection(sock)
            print(f"Connected to WALA server at {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            return False
    
    def authenticate(self):
        while True:
            print("\n=== WALA Chat Application ===")
            print("1. Login")
            print("2. Register")
            print("3. Quit")
            
            choice = input("Choose an option (1-3): ").strip()
            
            if choice == '1':
                if self.login():
                    return True
            elif choice == '2':
                if self.register():
                    return True
            elif choice == '3':
                return False
            else:
                print("Invalid choice. Please try again.")
    
    def login(self):
        try:
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            
            if not username or not password:
                print("Username and password cannot be empty.")
                return False
            
            message = protocol.create_login_message(username, password)
            self.connection.send(message)
            
            response = self.connection.receive()
            if not response:
                print("No response from server.")
                return False
            
            if response.type == config.MSG_TYPE_SUCCESS:
                print("Login successful!")
                self.username = username
                return True
            elif response.type == config.MSG_TYPE_ERROR:
                error_msg = response.data.get('error_message', 'Login failed')
                print(f"Login failed: {error_msg}")
                return False
            else:
                print("Unexpected response from server.")
                return False
                
        except Exception as e:
            print(f"Login error: {e}")
            return False
    
    def register(self):
        try:
            username = input("Choose username: ").strip()
            password = getpass.getpass("Choose password: ")
            password_confirm = getpass.getpass("Confirm password: ")
            
            if not username or not password:
                print("Username and password cannot be empty.")
                return False
            
            if password != password_confirm:
                print("Passwords do not match.")
                return False
            
            if len(password) < config.PASSWORD_MIN_LENGTH:
                print(f"Password must be at least {config.PASSWORD_MIN_LENGTH} characters long.")
                return False
            
            message = protocol.create_register_message(username, password)
            self.connection.send(message)
            
            response = self.connection.receive()
            if not response:
                print("No response from server.")
                return False
            
            if response.type == config.MSG_TYPE_SUCCESS:
                print("Registration successful!")
                self.username = username
                return True
            elif response.type == config.MSG_TYPE_ERROR:
                error_msg = response.data.get('error_message', 'Registration failed')
                print(f"Registration failed: {error_msg}")
                return False
            else:
                print("Unexpected response from server.")
                return False
                
        except Exception as e:
            print(f"Registration error: {e}")
            return False
    
    def generate_keys(self):
        try:
            print("Generating RSA key pair...")
            self.private_key, self.public_key = crypto_utils.generate_rsa_keypair()
            
            public_key_pem = crypto_utils.export_public_key(self.public_key).decode('utf-8')
            message = protocol.create_public_key_message(self.username, public_key_pem)
            self.connection.send(message)
            
            print("RSA keys generated and public key sent to server.")
            
        except Exception as e:
            print(f"Key generation error: {e}")
            raise
    
    def start_message_receiver(self):
        receiver_thread = threading.Thread(target=self.message_receiver, daemon=True)
        receiver_thread.start()
    
    def message_receiver(self):
        while self.running:
            try:
                message = self.connection.receive()
                if not message:
                    break
                
                self.handle_incoming_message(message)
                
            except Exception as e:
                if self.running:
                    print(f"\nError receiving message: {e}")
                break
    
    def handle_incoming_message(self, message):
        try:
            if message.type == config.MSG_TYPE_SESSION_KEY:
                self.handle_session_key_message(message)
                
            elif message.type == config.MSG_TYPE_CHAT_MESSAGE:
                self.handle_chat_message(message)
                
            elif message.type == config.MSG_TYPE_KEY_RESPONSE:
                self.handle_key_response(message)
                
            elif message.type == config.MSG_TYPE_KEY_ROTATION_REQUEST:
                self.handle_key_rotation_request(message)
                
            elif message.type == config.MSG_TYPE_ERROR:
                error_msg = message.data.get('error_message', 'Unknown error')
                print(f"\nServer error: {error_msg}")
                
            elif message.type == config.MSG_TYPE_USER_LIST:
                users = message.data.get('users', [])
                print(f"\nOnline users: {', '.join(users) if users else 'None'}")
                
            else:
                print(f"\nReceived unknown message type: {message.type}")
                
        except Exception as e:
            print(f"\nError handling incoming message: {e}")
    
    def handle_key_rotation_request(self, message):
        try:
            print("\n[SYSTEM] Server requested key rotation. Generating new RSA keys...")
            
            # Clear existing session keys
            self.session_keys.clear()
            
            # Generate new RSA key pair
            self.private_key, self.public_key = crypto_utils.generate_rsa_keypair()
            
            # Send new public key to server
            public_key_pem = crypto_utils.export_public_key(self.public_key).decode('utf-8')
            key_message = protocol.create_public_key_message(self.username, public_key_pem)
            self.connection.send(key_message)
            
            print("[SYSTEM] New RSA keys generated and sent to server. Session keys cleared.")
            
        except Exception as e:
            print(f"\n[SYSTEM] Error handling key rotation request: {e}")
    
    def handle_session_key_message(self, message):
        try:
            sender = message.sender
            
            if sender not in self.public_keys:
                if sender not in self.pending_session_keys:
                    self.pending_session_keys[sender] = []
                self.pending_session_keys[sender].append(message)
                
                self.request_public_key(sender)
                return
            
            encrypted_session_key = crypto_utils.decode_base64(message.data.get('encrypted_session_key', ''))
            signature = crypto_utils.decode_base64(message.data.get('signature', ''))
            
            try:
                session_key = crypto_utils.decrypt_session_key(encrypted_session_key, self.private_key)
            except Exception as decrypt_error:
                print(f"\n[SYSTEM] Failed to decrypt session key from {sender}")
                return
            
            try:
                if crypto_utils.verify_signature(session_key, signature, self.public_keys[sender]):
                    self.session_keys[sender] = session_key
                    print(f"\n[SYSTEM] Session key established with {sender}")
                    
                    if sender in self.pending_messages:
                        for pending_msg in self.pending_messages[sender]:
                            self.handle_chat_message(pending_msg)
                        del self.pending_messages[sender]
                else:
                    print(f"\n[SYSTEM] Session key signature verification failed for {sender}")
            except Exception as sig_error:
                print(f"\n[SYSTEM] Error verifying session key signature from {sender}")
                
        except Exception as e:
            print(f"\nError handling session key from {message.sender}: {e}")
    
    def handle_chat_message(self, message):
        try:
            sender = message.sender
            encrypted_content = crypto_utils.decode_base64(message.data.get('encrypted_content', ''))
            signature = crypto_utils.decode_base64(message.data.get('signature', ''))
            
            if sender not in self.session_keys:
                if sender not in self.pending_messages:
                    self.pending_messages[sender] = []
                self.pending_messages[sender].append(message)
                
                if sender not in self.public_keys:
                    self.request_public_key(sender)
                
                return
            
            try:
                plaintext = crypto_utils.decrypt_message(encrypted_content, self.session_keys[sender])
            except Exception as decrypt_error:
                print(f"\nError decrypting message from {sender}")
                return
            
            if sender in self.public_keys:
                try:
                    if crypto_utils.verify_signature(plaintext, signature, self.public_keys[sender]):
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        print(f"\n[{timestamp}] {sender}: {plaintext}")
                    else:
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        print(f"\n[{timestamp}] {sender}: {plaintext} [SIGNATURE VERIFICATION FAILED]")
                except Exception as sig_error:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    print(f"\n[{timestamp}] {sender}: {plaintext} [SIGNATURE ERROR]")
            else:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"\n[{timestamp}] {sender}: {plaintext} [UNVERIFIED]")
                
        except Exception as e:
            print(f"\nError handling chat message from {message.sender}: {e}")
    
    def handle_key_response(self, message):
        try:
            username = message.data.get('username')
            public_key_pem = message.data.get('public_key')
            
            if username and public_key_pem:
                public_key = crypto_utils.import_public_key(public_key_pem.encode('utf-8'))
                self.public_keys[username] = public_key
                
                if username in self.pending_session_keys:
                    for pending_session_msg in self.pending_session_keys[username]:
                        self.handle_session_key_message(pending_session_msg)
                    del self.pending_session_keys[username]
                
        except Exception as e:
            print(f"\nError handling public key response: {e}")
    
    def request_public_key(self, username):
        try:
            message = protocol.create_key_request_message(username)
            self.connection.send(message)
        except Exception as e:
            print(f"Error requesting public key for {username}: {e}")
    
    def establish_session_key(self, recipient):
        try:
            if recipient not in self.key_establishment_locks:
                self.key_establishment_locks[recipient] = threading.Lock()
            
            with self.key_establishment_locks[recipient]:
                if recipient in self.session_keys:
                    return True
                
                should_initiate = self.username < recipient
                
                if should_initiate:
                    if recipient not in self.public_keys:
                        self.request_public_key(recipient)
                        for i in range(50):
                            time.sleep(0.1)
                            if recipient in self.public_keys:
                                break
                        else:
                            print(f"[SYSTEM] Could not get public key for {recipient}")
                            return False
                    
                    session_key = crypto_utils.generate_session_key()
                    
                    encrypted_session_key = crypto_utils.encrypt_session_key(
                        session_key, self.public_keys[recipient]
                    )
                    
                    signature = crypto_utils.sign_message(session_key, self.private_key)
                    
                    message = protocol.create_session_key_message(
                        self.username, recipient,
                        crypto_utils.encode_base64(encrypted_session_key),
                        crypto_utils.encode_base64(signature)
                    )
                    self.connection.send(message)
                    
                    self.session_keys[recipient] = session_key
                    
                    return True
                else:
                    for i in range(10):
                        time.sleep(0.1)
                        if recipient in self.session_keys:
                            return True
                    
                    if recipient not in self.public_keys:
                        self.request_public_key(recipient)
                        for i in range(50):
                            time.sleep(0.1)
                            if recipient in self.public_keys:
                                break
                        else:
                            print(f"[SYSTEM] Could not get public key for {recipient}")
                            return False
                    
                    session_key = crypto_utils.generate_session_key()
                    
                    encrypted_session_key = crypto_utils.encrypt_session_key(
                        session_key, self.public_keys[recipient]
                    )
                    
                    signature = crypto_utils.sign_message(session_key, self.private_key)
                    
                    message = protocol.create_session_key_message(
                        self.username, recipient,
                        crypto_utils.encode_base64(encrypted_session_key),
                        crypto_utils.encode_base64(signature)
                    )
                    self.connection.send(message)
                    
                    self.session_keys[recipient] = session_key
                    
                    return True
            
        except Exception as e:
            print(f"Error establishing session key with {recipient}: {e}")
            return False
    
    def send_message(self, recipient, message_text):
        try:
            if not self.establish_session_key(recipient):
                return False
            
            encrypted_content = crypto_utils.encrypt_message(
                message_text, self.session_keys[recipient]
            )
            
            signature = crypto_utils.sign_message(message_text, self.private_key)
            
            message = protocol.create_chat_message(
                self.username, recipient,
                crypto_utils.encode_base64(encrypted_content),
                crypto_utils.encode_base64(signature)
            )
            self.connection.send(message)
            
            return True
            
        except Exception as e:
            print(f"Error sending message to {recipient}: {e}")
            return False
    
    def list_users(self):
        try:
            message = protocol.create_user_list_message([])
            self.connection.send(message)
        except Exception as e:
            print(f"Error requesting user list: {e}")
    
    def chat_interface(self):
        print(f"\n=== Welcome to WALA Chat, {self.username}! ===")
        print("Commands:")
        print("  /msg <user> <message>  - Send a message to a user")
        print("  /users                 - List online users")
        print("  /help                  - Show this help")
        print("  /quit                  - Exit the application")
        print("\nType your commands below:")
        
        while self.running:
            try:
                user_input = input().strip()
                
                if not user_input:
                    continue
                
                if user_input.startswith('/msg '):
                    parts = user_input[5:].split(' ', 1)
                    if len(parts) < 2:
                        print("Usage: /msg <user> <message>")
                        continue
                    
                    recipient, message_text = parts
                    if self.send_message(recipient, message_text):
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        print(f"[{timestamp}] You -> {recipient}: {message_text}")
                    
                elif user_input == '/users':
                    self.list_users()
                    
                elif user_input == '/help':
                    print("Commands:")
                    print("  /msg <user> <message>  - Send a message to a user")
                    print("  /users                 - List online users")
                    print("  /help                  - Show this help")
                    print("  /quit                  - Exit the application")
                    
                elif user_input == '/quit':
                    break
                    
                else:
                    print("Unknown command. Type /help for available commands.")
                    
            except EOFError:
                break
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error in chat interface: {e}")
    
    def run(self):
        try:
            if not self.connect_to_server():
                return False
            
            if not self.authenticate():
                return False
            
            self.generate_keys()
            
            self.running = True
            self.start_message_receiver()
            
            self.chat_interface()
            
            return True
            
        except Exception as e:
            print(f"Client error: {e}")
            return False
        finally:
            self.shutdown()
    
    def shutdown(self):
        if not self.running:
            return
        
        print("\nShutting down client...")
        self.running = False
        
        if self.connection and not self.connection.is_closed():
            try:
                message = protocol.create_logout_message()
                self.connection.send(message)
            except:
                pass
        
        if self.connection:
            self.connection.close()
        
        print("Client shutdown complete.")


def main():
    server_host = config.DEFAULT_SERVER_HOST
    server_port = config.DEFAULT_SERVER_PORT
    
    if len(sys.argv) > 1:
        server_host = sys.argv[1]
    
    if len(sys.argv) > 2:
        try:
            server_port = int(sys.argv[2])
        except ValueError:
            print(f"Invalid port number: {sys.argv[2]}")
            sys.exit(1)
    
    client = WALAClient(server_host, server_port)
    
    try:
        success = client.run()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        client.shutdown()
        sys.exit(0)
    except Exception as e:
        print(f"Client error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()