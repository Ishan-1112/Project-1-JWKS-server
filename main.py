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

# Encode private key to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Key ID and expiry timestamp
kid = "key1"
expiry = datetime.utcnow() + timedelta(days=30)

keys = {
    kid: {
        "private_key": private_key,
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
                "n": int.from_bytes(private_key.public_key().public_numbers().n.to_bytes((private_key.public_key().key_size + 7) // 8, byteorder="big"), "big"),
                "e": private_key.public_key().public_numbers().e
            })
    return jsonify(keys={"keys": jwks_keys})

@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired')
    if expired:
        key = keys[kid]
    else:
        key = next(iter(keys.values()))

    # Sign the JWT token using the RSA private key
    token = jwt.encode({'some': 'payload'}, key['private_key'], algorithm='RS256', headers={'kid': kid})
    return jsonify({'access_token': token})

if __name__ == '__main__':
    app.run(port=8080)
