from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import jwt

app = Flask(__name__)

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Encode keys to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Key ID and expiry timestamp
kid = "key1"
expiry = datetime.utcnow() + timedelta(days=30)

keys = {
    kid: {
        "public_key": public_pem.decode('utf-8'),
        "expiry": expiry
    }
}

@app.route('/')
def index():
    return "Welcome to the JWKS server!"

@app.route('/jwks', methods=['GET'])
def jwks():
    jwks_keys = []
    for key_id, key_data in keys.items():
        if key_data["expiry"] > datetime.utcnow():
            jwks_keys.append({
                "kid": key_id,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": jwt.utils.bytes_to_number(public_key.public_numbers().n).to_bytes((jwt.utils.num_bits(public_key.public_numbers().n) + 7) // 8, byteorder="big").decode('utf-8'),
                "e": jwt.utils.bytes_to_number(public_key.public_numbers().e).to_bytes((jwt.utils.num_bits(public_key.public_numbers().e) + 7) // 8, byteorder="big").decode('utf-8')
            })
    return jsonify(keys={"keys": jwks_keys})

@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired')
    if expired:
        key = keys[kid]
    else:
        key = next(iter(keys.values()))
    token = jwt.encode({'some': 'payload'}, key['public_key'], algorithm='RS256', headers={'kid': kid})
    return jsonify({'access_token': token})

if __name__ == '__main__':
    app.run(port=8080)
