"""
network communication protocol for WALA (message serialization, deserialization, and network I/O)
"""

import json
import socket
import struct
import threading
import config


class ProtocolError(Exception):
    pass


class Message:
    
    def __init__(self, msg_type, data=None, sender=None, recipient=None):
        self.type = msg_type
        self.data = data or {}
        self.sender = sender
        self.recipient = recipient
        self.timestamp = None
    
    def to_dict(self):
        return {
            'type': self.type,
            'data': self.data,
            'sender': self.sender,
            'recipient': self.recipient,
            'timestamp': self.timestamp
        }
    
    @classmethod
    def from_dict(cls, msg_dict):
        msg = cls(
            msg_type=msg_dict['type'],
            data=msg_dict.get('data', {}),
            sender=msg_dict.get('sender'),
            recipient=msg_dict.get('recipient')
        )
        msg.timestamp = msg_dict.get('timestamp')
        return msg
    
    def __str__(self):
        return f"Message(type={self.type}, sender={self.sender}, recipient={self.recipient})"


def send_message(sock, message):
    try:
        msg_dict = message.to_dict()
        msg_json = json.dumps(msg_dict)
        msg_bytes = msg_json.encode('utf-8')
        length = len(msg_bytes)
        length_prefix = struct.pack('!I', length)
        sock.sendall(length_prefix + msg_bytes)
    except Exception as e:
        raise ProtocolError(f"Failed to send message: {e}")


def receive_message(sock):
    try:
        length_data = receive_exact(sock, 4)
        if not length_data:
            return None
        length = struct.unpack('!I', length_data)[0]
        msg_bytes = receive_exact(sock, length)
        if not msg_bytes:
            return None
        msg_json = msg_bytes.decode('utf-8')
        msg_dict = json.loads(msg_json)
        return Message.from_dict(msg_dict)
    except Exception as e:
        raise ProtocolError(f"Failed to receive message: {e}")


def receive_exact(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data


class SecureConnection:
    
    def __init__(self, sock):
        self.socket = sock
        self.lock = threading.Lock()
        self.closed = False
    
    def send(self, message):
        with self.lock:
            if self.closed:
                raise ProtocolError("Connection is closed")
            send_message(self.socket, message)
    
    def receive(self):
        if self.closed:
            raise ProtocolError("Connection is closed")
        return receive_message(self.socket)
    
    def close(self):
        with self.lock:
            if not self.closed:
                self.closed = True
                try:
                    self.socket.close()
                except:
                    pass
    
    def is_closed(self):
        return self.closed


def create_login_message(username, password):
    return Message(
        msg_type=config.MSG_TYPE_LOGIN,
        data={'username': username, 'password': password}
    )


def create_register_message(username, password):
    return Message(
        msg_type=config.MSG_TYPE_REGISTER,
        data={'username': username, 'password': password}
    )


def create_public_key_message(username, public_key_pem):
    return Message(
        msg_type=config.MSG_TYPE_PUBLIC_KEY,
        data={'username': username, 'public_key': public_key_pem}
    )


def create_key_request_message(target_username):
    return Message(
        msg_type=config.MSG_TYPE_KEY_REQUEST,
        data={'target_username': target_username}
    )


def create_key_response_message(username, public_key_pem):
    return Message(
        msg_type=config.MSG_TYPE_KEY_RESPONSE,
        data={'username': username, 'public_key': public_key_pem}
    )


def create_session_key_message(sender, recipient, encrypted_session_key, signature):
    return Message(
        msg_type=config.MSG_TYPE_SESSION_KEY,
        sender=sender,
        recipient=recipient,
        data={
            'encrypted_session_key': encrypted_session_key,
            'signature': signature
        }
    )


def create_chat_message(sender, recipient, encrypted_content, signature):
    return Message(
        msg_type=config.MSG_TYPE_CHAT_MESSAGE,
        sender=sender,
        recipient=recipient,
        data={
            'encrypted_content': encrypted_content,
            'signature': signature
        }
    )


def create_key_rotation_request_message():
    return Message(
        msg_type=config.MSG_TYPE_KEY_ROTATION_REQUEST,
        data={'reason': 'Periodic key rotation'}
    )


def create_error_message(error_code, error_msg):
    return Message(
        msg_type=config.MSG_TYPE_ERROR,
        data={'error_code': error_code, 'error_message': error_msg}
    )


def create_success_message(message=None):
    data = {}
    if message:
        data['message'] = message
    return Message(
        msg_type=config.MSG_TYPE_SUCCESS,
        data=data
    )


def create_user_list_message(users):
    return Message(
        msg_type=config.MSG_TYPE_USER_LIST,
        data={'users': users}
    )


def create_logout_message():
    return Message(msg_type=config.MSG_TYPE_LOGOUT)


def validate_message(message):
    if not isinstance(message, Message):
        return False
    
    if not message.type:
        return False
    
    valid_types = [
        config.MSG_TYPE_LOGIN,
        config.MSG_TYPE_REGISTER,
        config.MSG_TYPE_PUBLIC_KEY,
        config.MSG_TYPE_SESSION_KEY,
        config.MSG_TYPE_CHAT_MESSAGE,
        config.MSG_TYPE_KEY_REQUEST,
        config.MSG_TYPE_KEY_RESPONSE,
        config.MSG_TYPE_KEY_ROTATION_REQUEST,
        config.MSG_TYPE_ERROR,
        config.MSG_TYPE_SUCCESS,
        config.MSG_TYPE_USER_LIST,
        config.MSG_TYPE_LOGOUT
    ]
    
    if message.type not in valid_types:
        return False
    
    if message.type in [config.MSG_TYPE_SESSION_KEY, config.MSG_TYPE_CHAT_MESSAGE]:
        if not message.sender or not message.recipient:
            return False
    
    return True


def get_message_size(message):
    msg_dict = message.to_dict()
    msg_json = json.dumps(msg_dict)
    return len(msg_json.encode('utf-8'))


def create_client_socket(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        return sock
    except Exception as e:
        raise ProtocolError(f"Failed to connect to {host}:{port}: {e}")


def create_server_socket(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        return sock
    except Exception as e:
        raise ProtocolError(f"Failed to bind to {host}:{port}: {e}")