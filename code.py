#Name: Divya Darji
# CSCE 3550.002
# Project 1
# I added comments for better understanding

# Import necessary libraries
import http.server
import json
import base64
import time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Define the port on which the server will listen
PORT = 8080

# Generate an RSA key pair for signing JWTs
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Serialize the private key to PEM format for storage or transmission
private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

# Extract the public key from the generated private key
public_key = private_key.public_key()

# Serialize the public key to PEM format
public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

# Define key ID and expiry times for JWTs
kid = "my_kid"
expiry = int(time.time()) + 3600  # JWT will expire in 1 hour
expired_kid = "expired_kid"
expired_expiry = int(time.time()) - 3600  # Represents an already expired JWT

# Function to create a JWT with either a valid or expired expiry time
def create_jwt(payload, private_key, expired=False):
    # Define JWT header with algorithm and type information
    header = {"alg": "RS256", "typ": "JWT", "kid": expired_kid if expired else kid}
    # Set the expiry time in the payload
    payload['exp'] = expired_expiry if expired else expiry
    # Encode the header and payload using base64 URL-safe encoding
    header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    # Concatenate the encoded header and payload
    signing_input = f"{header_encoded}.{payload_encoded}"
    # Sign the concatenated string using the private key
    signature = private_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    # Encode the signature using base64 URL-safe encoding
    signature_encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    # Return the complete JWT as a string
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

# Custom HTTP request handler class for serving JWKS and creating JWTs
class JWKSHandler(http.server.SimpleHTTPRequestHandler):
    # Handle GET requests
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            # Prepare JWKS response containing the public key information
            jwks = {
                "keys": [{
                    "kty": "RSA",
                    "kid": kid,
                    "use": "sig",
                    "alg": "RS256",
                    "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, byteorder='big')).decode(),
                    "e": base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes(3, byteorder='big')).decode(),
                }]
            }
            # Send the JWKS response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(jwks).encode())
        else:
            # Handle requests to other paths
            self.send_error(404, "Resource not found")

    # Handle POST requests
    def do_POST(self):
        # Get the content length from the request header
        content_length = int(self.headers['Content-Length'])
        # Read the request body
        post_data = self.rfile.read(content_length)
        try:
            # Parse the request body as JSON
            request_data = json.loads(post_data.decode('utf-8'))
            # Check if an expired JWT is requested
            expired_requested = request_data.get('expired', False)
            # Create a JWT payload with username and expiry time
            payload = {"username": "userABC", "exp": expired_expiry if expired_requested else expiry}
            # Generate a JWT using the private key
            jwt_token = create_jwt(payload, private_key, expired_requested)
            # Send the JWT in the response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"token": jwt_token}).encode())
        except json.JSONDecodeError:
            # Handle invalid JSON data in the request
            self.send_error(400, "Invalid JSON data")

    # Optionally suppress server logging to stdout for cleaner output
    def log_message(self, format, *args):
        return

# Main function to start the HTTP server
if __name__ == "__main__":
    server_address = ('', PORT)
    httpd = http.server.HTTPServer(server_address, JWKSHandler)
    print(f"Server started on port {PORT}")
    httpd.serve_forever()
