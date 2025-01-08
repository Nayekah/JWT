import json
import time
import base64
import hashlib
from flask import Flask, request, jsonify
from Crypto.Util.number import getPrime, GCD
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class UserManager:
    def __init__(self):
        self.users = {}
        
        while True:
            p = getPrime(1024)
            q = getPrime(1024)
            e = 65537

            if p == q:
                continue

            n = p * q
            phi = (p - 1) * (q - 1)

            if GCD(e, phi) == 1:
                break
        
        d = pow(e, -1, phi)

        self.private_key = rsa.RSAPrivateNumbers(
            p=p,
            q=q,
            d=d,
            dmp1=d % (p - 1),
            dmq1=d % (q - 1),
            iqmp=pow(q, -1, p),
            public_numbers=rsa.RSAPublicNumbers(
                e=e,
                n=n
            )
        ).private_key()

        self.public_key = self.private_key.public_key()
        
        self.private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # LCG parameters
        self.lcg_a = 1664525
        self.lcg_c = 1013904223
        self.lcg_m = 2**32
        self.lcg_seed = int(time.time())

    def get_public_key(self):
        return self.public_pem.decode()

    def generate_salt(self, length=16):
        salt = bytearray()
        for _ in range(length):
            self.lcg_seed = (self.lcg_a * self.lcg_seed + self.lcg_c) % self.lcg_m
            salt.append(self.lcg_seed % 256)
        return bytes(salt)

    def register_user(self, username, password):
        if username in self.users:
            raise ValueError("Username already exists")
        
        salt = self.generate_salt()
        hashed_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000
        )
        
        encrypted_password = self.public_key.encrypt(
            hashed_password,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        self.users[username] = {
            'encrypted_password': base64.b64encode(encrypted_password).decode(),
            'salt': salt.hex()
        }
        
        return True

    def verify_user(self, username, password):
        if username not in self.users:
            return False
            
        user_data = self.users[username]
        salt = bytes.fromhex(user_data['salt'])
        
        input_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000
        )
        
        try:
            stored_hash = self.private_key.decrypt(
                base64.b64decode(user_data['encrypted_password']),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return input_hash == stored_hash
        except:
            return False

    def generate_token(self, username):
        user_data = self.users[username]
        
        payload = {
            'username': username,
            'exp': int(time.time()) + 3600,
            'credentials': user_data['encrypted_password']
        }
        
        payload_str = json.dumps(payload, sort_keys=True)
        payload['hash'] = hashlib.sha256(payload_str.encode()).hexdigest()
        
        header = {
            'alg': 'RS256',
            'typ': 'JWT'
        }
        
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
        
        message = header_encoded + b'.' + payload_encoded
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        signature_encoded = base64.urlsafe_b64encode(signature).rstrip(b'=')
        
        return b'.'.join([header_encoded, payload_encoded, signature_encoded]).decode()

app = Flask(__name__)
user_manager = UserManager()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
        
    try:
        user_manager.register_user(username, password)
        return jsonify({'message': 'Registration successful'})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
        
    if user_manager.verify_user(username, password):
        token = user_manager.generate_token(username)
        return jsonify({'token': token})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/public-key', methods=['GET'])
def get_public_key():
    return jsonify({'public_key': user_manager.get_public_key()})

app.run(debug=True, port=1220)