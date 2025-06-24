from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import os
import base64

def load_certificate(cert_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
    return cert


def load_public_key(key_path):
    with open(key_path, "rb") as k:
        key_data = k.read()
        key = serialization.load_pem_public_key(key_data)
    return key


def load_private_key(key_path, password=None):
    with open(key_path, "rb") as k:
        key_data = k.read()
        key = serialization.load_pem_private_key(key_data, password=password)
    return key

# Converter chave para string (base64)
def key_to_base64(key):
    return base64.b64encode(key).decode('utf-8')

# Converter chave de volta para bytes (base64)
def base64_to_key(base64_key):
    return base64.b64decode(base64_key.encode('utf-8'))

# Carregar chave RSA de bytes
def load_public_key_from_bytes(key_bytes):
    return serialization.load_pem_public_key(key_bytes)


def load_private_key_from_bytes(key_bytes):
    return serialization.load_pem_private_key(key_bytes, password=None)


def save_topic_key(topic: str, key: bytes, key_dir: str):
    key_path = os.path.join(key_dir, f"{topic}.key")
    with open(key_path, "wb") as f:
        f.write(key)
   
    
def generate_and_save_topic_key(topic: str, key_dir: str):
    key_path = os.path.join(key_dir, f"{topic}.key")
    key = Fernet.generate_key()
    with open(key_path, "wb") as f:
        f.write(key)
    return key_to_base64(key)


def delete_saved_key(topic, key_dir):
    key_path = os.path.join(key_dir, f"{topic}.key")
    if os.path.exists(key_path):
        os.remove(key_path)
        print(f"Key for topic {topic} was deleted")
    else:
        print(f"Key for topic {topic} was not found")


def load_keys_from_dir(path):
    all_saved_keys = {}
    for file_name in os.listdir(path):
        full_path = os.path.join(path, file_name)
        with open(full_path, "rb") as f:
            key = f.read()
        key_name = os.path.splitext(os.path.basename(file_name))[0]
        all_saved_keys[key_name] = key_to_base64(key)
    return all_saved_keys


def verify_certificate_signature(signing_cert, cert):
    signing_key = signing_cert.public_key()
    try:
        signing_key.verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm,
        )
        return True
    except Exception as e:
        return False


def asymmetric_encrypt(to_be_encrypted, key_to_encrypt):
    ciphertext = key_to_encrypt.encrypt(
        to_be_encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def asymmetric_decrypt(to_be_decrypted, key_to_decrypt):
    plaintext = key_to_decrypt.decrypt(
        to_be_decrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


def signing(private_key, msg):
    signature = private_key.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return signature


def verification_of_signature(public_key, msg, signature):
    try:
        public_key.verify(
            signature,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        return False

if __name__ == "__main__":
    #all_keys = load_keys_from_dir(r"src\security\client_keys")
    #print(all_keys)
    key = Fernet.generate_key()
    f = Fernet(key)
    
    a = 'Oie'
    cr = f.encrypt(a.encode())
    plain = f.decrypt(cr)
    print(a)
    print(cr)
    print(cr.decode())
    print(plain.decode())

    
    