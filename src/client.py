import socket
import json
import threading
from security.auth import *
from cryptography import x509
from cryptography.fernet import Fernet
import os
import base64

class Client: 
    def __init__(self, client_id, host="127.0.0.1", port=5000):
        self.client_id = client_id
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.KEY_DIR = f"src/security/keys"
        self.CERT_DIR = f"src/security/certificates"
        self.TOPIC_KEY_DIR = f"src/security/topic_keys"
        self.CA_CERT_PATH = f"{self.CERT_DIR}/ca.crt"
        self.PUBLIC_KEY_PATH = f"{self.KEY_DIR}/public_key_{client_id}.pem"
        self.PRIVATE_KEY_PATH = f"{self.KEY_DIR}/private_key_{client_id}.pem"
        self.CLIENT_CERT_PATH = f"{self.CERT_DIR}/client{client_id}.crt"
            
        self.public_key = load_public_key(self.PUBLIC_KEY_PATH)
        self.private_key = load_private_key(self.PRIVATE_KEY_PATH)
        
        self.running = True
        self.session_key = Fernet(Fernet.generate_key())
        self.topic_keys: dict[str, str] = {}

    def _finish(self, msg):
        print(msg)
        self.running = False
        self.socket.close()

    def _send_file(self, filePath):
        with open(filePath, "rb") as f:
            file_data = f.read()
            cert_size = len(file_data)
            self.socket.sendall(cert_size.to_bytes(4, byteorder="big"))
            self.socket.sendall(file_data)
        print("✅ The client certification was sent to the broker")

    def _receive_data(self):
        size_bytes = self.socket.recv(4)
        if not size_bytes:
            raise Exception("[ERROR] receiving data size")

        size = int.from_bytes(size_bytes, byteorder="big")
        data = b""
        while len(data) < size:
            chunk = self.socket.recv(min(2048, size - len(data)))
            if not chunk:
                raise Exception("[ERROR] receiving data")
            data += chunk
        return data

    def _send_data(self, data):
        self.socket.sendall(len(data).to_bytes(4, byteorder="big"))
        self.socket.sendall(data)

    def _auth_handshake(self):
        try:
            # The client receives the client certificate and its challenge
            cert_bytes = self._receive_data()
            msg_bytes = self._receive_data()
            signature_bytes = self._receive_data()

            if cert_bytes:
                broker_cert = x509.load_pem_x509_certificate(cert_bytes)
                ca_cert = load_certificate(self.CA_CERT_PATH)
            else:
                raise Exception("[ERROR] reading broker crt")

            if verify_certificate_signature(ca_cert, broker_cert):
                print("✅ The broker certification was signed by the CA.")
            else:
                raise Exception("❌ The broker certification was not signed by the CA")

            broker_public_key = broker_cert.public_key()
            if verification_of_signature(broker_public_key, msg_bytes, signature_bytes):
                print("✅ The broker passed its challenge.")
            else:
                raise Exception("❌ The broker failed its challenge")

            # The client sends its certificate and a challenge
            self._send_file(self.CLIENT_CERT_PATH)
            msg = os.urandom(32)
            signature = signing(self.private_key, msg)
            self._send_data(msg)
            self._send_data(signature)

            # The client receives the ciphered session key
            cipher_session_key = self._receive_data()
            self.session_key = Fernet(asymmetric_decrypt(cipher_session_key, self.private_key))
            print("✅ Digital Envelope with broker confirmed.\n")

        except Exception as e:
            self._finish(e)

    def _receive_msg(self):
        cipher_data = self._receive_data()
        if cipher_data:
            data = self.session_key.decrypt(cipher_data)
            message = json.loads(data.decode())
            return message

    def _format_and_send_msg(self, cmd, topic=None, content=None):
        data = {"cmd": cmd}
        if topic:
            data["topic"] = topic
        if content:
            data["content"] = content
        raw = json.dumps(data).encode()
        encrypted = self.session_key.encrypt(raw)
        self._send_data(encrypted)

    def _listen_to_broker(self):
        while self.running:
            try:
                message = self._receive_msg()
                if message:
                    topic = message["topic"]
                    
                    #TODO fix this flux
                    if message["cmd"] == "create":
                        if message["content"] == "success":
                            key = generate_and_save_topic_key(topic, self.TOPIC_KEY_DIR)
                            self.topic_keys[topic] = key
                            print(f"{topic} was created")
                        elif message["content"] == "all_clear":
                            print(f"All the keys have been sent")   
                        else:
                            print(f"{topic} already exists")

                    elif message["cmd"] == "subscribe":
                        if message["content"] == "success":
                            print(f"You subscribed to {topic}")
                        else:
                            print(f"{topic} does not exist")

                    elif message["cmd"] == "unsubscribe":
                        if message["content"] == "success":
                            print(f"You unsubscribed from {topic}")
                        else:
                            print(f"You failed to usubscribed from {topic}")

                    elif message["cmd"] == "publish":
                        if message["content"] == "success":
                            print(f"Publish to the topic {topic} was delivered")
                        else:
                            print(f"Failed to publish to the topic {topic}")

                    # Must encrypt a topic key with the public key that it received
                    elif message["cmd"] == "keys":
                        
                        key = base64_to_key(self.topic_keys[message['topic']])
                        rcv_pub_key = load_public_key_from_bytes(base64_to_key(message['content']))
                        cipher_key = asymmetric_encrypt(key, rcv_pub_key)
                        cipher_key_str = key_to_base64(cipher_key)
                        self._format_and_send_msg('keys', topic, cipher_key_str)
                                        
                   # I think its done      
                    elif message["cmd"] == "topic_key":
                        cipher_key = base64_to_key(message['content'])                    
                        key = asymmetric_decrypt(cipher_key, self.private_key)
                        save_topic_key(topic, key, self.TOPIC_KEY_DIR)
                        self.topic_keys[topic] = key_to_base64(key)
                    
                    # Receives an actual msg from the broker
                    elif message["cmd"] == "msg":
                        key = Fernet(base64_to_key(self.topic_keys[topic]))
                        plaintext = key.decrypt(message['content'].encode()).decode()
                        print(f'[{topic}]: {plaintext}')
                    
                    else:
                        print("Message was not formatted properly")
            except Exception as e:
                self._finish(f"[ERROR] in listener: {e}")

    def _create(self, topic):
        if topic in self.topic_keys:
            print(f'The topic "{topic}" already exists')
            return
        self._format_and_send_msg("create", topic)

    def _subscribe(self, topic):
        if topic in self.topic_keys:
            print(f'You are already subscribed to the topic "{topic}"')
            return
        self._format_and_send_msg("subscribe", topic)

    def _publish(self, topic, msg):
        if topic not in self.topic_keys:
            print(f'You must be subscribed to the topic "{topic}" to publish there')
            return
        topic_key = Fernet(base64_to_key(self.topic_keys[topic]))
        encrypted_msg = topic_key.encrypt(msg.encode())
        self._format_and_send_msg("publish", topic, encrypted_msg.decode())
    
    def _unsubscribe(self, topic):
        if topic not in self.topic_keys:
            print(f'You do not have the topic "{topic}" saved locally')
        self.topic_keys.pop(topic)
        delete_saved_key(topic, self.TOPIC_KEY_DIR)
        self._format_and_send_msg("unsubscribe", topic)

    def run(self):
        try:
            self.topic_keys = load_keys_from_dir(self.TOPIC_KEY_DIR)
            self.socket.connect((self.host, self.port))
            print(f"\nConnected to server at {self.host}:{self.port}")
            self._auth_handshake()
            
            print("\nAvailable commands: ")
            print("- create <topic>")
            print("- subscribe <topic>")
            print("- publish <topic> <message>")
            print("- unsubscribe <topic>")
            print("- exit\n")
            
            threading.Thread(target=self._listen_to_broker, daemon=True).start()
            
            while self.running:
                try:
                    command = input("").strip()
                    if command == "exit":
                        self._format_and_send_msg("exit")
                        break

                    elif command.startswith("create "):
                        _, topic = command.split(maxsplit=1)
                        self._create(topic)

                    elif command.startswith("subscribe "):
                        _, topic = command.split(maxsplit=1)
                        self._subscribe(topic)

                    elif command.startswith("unsubscribe "):
                        _, topic = command.split(maxsplit=1)
                        self._unsubscribe(topic)

                    elif command.startswith("publish "):
                        _, topic, msg = command.split(maxsplit=2)
                        self._publish(topic, msg)

                    else:
                        print("Unknown command")
                        
                except ValueError:
                    print("Please format your command properly")

        except Exception as e:
            self._finish(f"[ERROR]: {e}")

if __name__ == "__main__":
    Client(client_id=2).run()
