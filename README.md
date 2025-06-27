# 🔐 Secure TLS MQTT Client

This is a university project implementing a **secure MQTT-like client** that connects to a custom broker using certificates, digital signatures, and both asymmetric and symmetric encryption to simulate TLS. The goal is to enable end-to-end encrypted publish/subscribe messaging between clients through a broker.

## 📚 Overview

This project implements a secure client that:

- Authenticates the broker using **X.509 certificates**.
- Proves possession of private key using **digital signatures**.
- Exchanges **symmetric session keys** securely using **asymmetric encryption**.
- Manages **encrypted topics** and securely publishes/subscribes to messages.
- Supports MQTT-style commands: `create`, `subscribe`, `publish`, `unsubscribe`, and `exit`.

## ⚙️ Features

✅ TLS-based mutual authentication (broker & client certificates)  
✅ Digital envelope with Fernet symmetric key encryption  
✅ Asymmetric encryption (RSA) for secure key exchange  
✅ End-to-end encrypted messaging using Fernet  
✅ Topic-based key management and secure messaging  
✅ Real-time command interface with asynchronous listening  

## 🗂️ Project Structure

```
project-root/
│
├── src/
│   ├── client.py                 # Main client class
│   └── security/
│       ├── auth.py               # Cryptographic utilities (RSA, Fernet, certificates)
│       ├── keys/                 # Client public/private keys (PEM format)
│       ├── certificates/         # Client certificate and CA certificate (.crt)
│       └── topic_keys/           # Encrypted topic keys saved locally per client
```

## 🚀 How It Works

1. **Client connects to the broker**
2. **Mutual TLS handshake**:
   - Receives the broker's certificate and signed challenge
   - Verifies the broker's certificate using the CA
   - Verifies the broker's signature
   - Sends its certificate and signed challenge in response
3. **Session key exchange**:
   - Receives an encrypted Fernet key from the broker
   - Decrypts it using its private key
   - Uses it for secure session communication

## 📬 Commands Supported

| Command        | Description                                                                         |
|----------------|-------------------------------------------------------------------------------------|
| `create`       | Creates a new topic and sends the topic key encrypted to all known clients         |
| `subscribe`    | Subscribes to a topic, receives the topic key, and synchronizes previous messages  |
| `publish`      | Publishes a message encrypted with the topic key                                   |
| `unsubscribe`  | Removes local topic key and unsubscribes from the topic                            |
| `exit`         | Gracefully disconnects and stops the client                                     |

## 🔐 Security Details

- 🔑 **Symmetric Encryption**: All messages and session communication are encrypted using `Fernet`.
- 🔏 **Asymmetric Encryption**: RSA is used for securely exchanging topic/session keys.
- 📜 **Certificates**: Client and broker use `.crt` X.509 certificates for authentication.
- ✍️ **Digital Signatures**: Ensures that parties truly possess the matching private keys.

## 🛠 Requirements

- Python 3.10+
- `cryptography` library  
  Install with:

```bash
pip install -r requirements.txt
```

## 🧪 Running the Client

```bash
python src/client.py
```

Default host is set to `127.0.0.1`. You can change it to your broker’s IP for LAN testing.

## 📄 License

This project is intended for **educational use** only.  
