#!/usr/bin/env python3
"""
HTTPS Server for QMS Frontend
Serves the index.html with SSL encryption using mkcert certificates
"""
import http.server
import socketserver
import ssl
import os
import sys

# Configuration
PORT = 8000
HOST = "0.0.0.0"
CERT_FILE = "localhost+3.pem"
KEY_FILE = "localhost+3-key.pem"

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add security headers
        self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        super().end_headers()

if __name__ == "__main__":
    # Check if SSL certificates exist
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print(f"❌ SSL certificates not found!")
        print(f"Expected files: {CERT_FILE}, {KEY_FILE}")
        print("Run: mkcert localhost 127.0.0.1 ::1 10.237.138.1")
        sys.exit(1)
    
    # Create HTTPS server
    with socketserver.TCPServer((HOST, PORT), MyHTTPRequestHandler) as httpd:
        # Wrap with SSL
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        
        print("\n" + "="*60)
        print("🔒 QMS HTTPS Frontend Server")
        print("="*60)
        print(f"🌐 Local:   https://localhost:{PORT}")
        print(f"🌐 Network: https://10.237.138.1:{PORT}")
        print("="*60)
        print("✅ SSL encryption enabled")
        print("✅ Security headers configured")
        print("✅ Ready for quantum-secure messaging")
        print("="*60)
        print("Press Ctrl+C to stop\n")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Server stopped")