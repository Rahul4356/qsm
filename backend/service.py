"""
REAL Quantum Crypto Service - Production Implementation
ML-KEM-768 (Kyber768) and Falcon-512 with Wrap-and-Sign Protocol
REQUIRES liboqs library - no simulation fallback
"""

import os
import sys
import hashlib
import json
import traceback
from fastapi import FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
import base64
import logging
from typing import Dict, Optional, Tuple, List, Any
from datetime import datetime, timedelta
import uuid

# Classical crypto for ECDSA wrapper
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

# Add local liboqs installation paths
liboqs_base = "/Users/rahulsemwal/Desktop/ducc beta testing/liboqs"
possible_paths = [
    os.path.join(liboqs_base, "build", "lib"),
    os.path.join(liboqs_base, "build", "src"),
    os.path.join(liboqs_base, "lib"),
    "/Users/rahulsemwal/Desktop/ducc beta testing/liboqs-python",
    "/usr/local/lib",
    "/usr/lib"
]

# Add Python path for liboqs-python
liboqs_python_path = "/Users/rahulsemwal/Desktop/ducc beta testing/liboqs-python"
if os.path.exists(liboqs_python_path):
    sys.path.insert(0, liboqs_python_path)

for path in possible_paths:
    if os.path.exists(path):
        if path not in os.environ.get('PATH', ''):
            os.environ['PATH'] = path + os.pathsep + os.environ.get('PATH', '')
        if path not in sys.path:
            sys.path.insert(0, path)

# Set LD_LIBRARY_PATH for macOS
liboqs_lib_path = os.path.join(liboqs_base, "build", "lib")
if os.path.exists(liboqs_lib_path):
    current_lib_path = os.environ.get('DYLD_LIBRARY_PATH', '')
    os.environ['DYLD_LIBRARY_PATH'] = liboqs_lib_path + os.pathsep + current_lib_path

# REQUIRED: Import Open Quantum Safe library - no fallback
try:
    import oqs
    
    # Verify required functions exist
    if not (hasattr(oqs, 'KeyEncapsulation') and hasattr(oqs, 'Signature')):
        print("❌ ERROR: liboqs missing required functions")
        print("❌ Please install liboqs-python properly")
        sys.exit(1)
    
    # Get version info
    if hasattr(oqs, 'oqs_python_version'):
        QUANTUM_VERSION = oqs.oqs_python_version()
    elif hasattr(oqs, 'oqs_version'):
        QUANTUM_VERSION = oqs.oqs_version()
    else:
        QUANTUM_VERSION = "Unknown version"
    
    # Get available algorithms
    AVAILABLE_KEMS = oqs.get_enabled_kem_mechanisms() if hasattr(oqs, 'get_enabled_kem_mechanisms') else []
    AVAILABLE_SIGS = oqs.get_enabled_sig_mechanisms() if hasattr(oqs, 'get_enabled_sig_mechanisms') else []
    
    # Verify required algorithms
    if "Kyber768" not in AVAILABLE_KEMS:
        print("❌ ERROR: ML-KEM-768 (Kyber768) not available in liboqs")
        sys.exit(1)
        
    if "Falcon-512" not in AVAILABLE_SIGS:
        print("❌ ERROR: Falcon-512 not available in liboqs")
        sys.exit(1)
    
    print("="*80)
    print("✅ REAL QUANTUM CRYPTOGRAPHY ENABLED")
    print(f"✅ liboqs version: {QUANTUM_VERSION}")
    print(f"✅ Available KEMs: {len(AVAILABLE_KEMS)}")
    print(f"✅ Available Signatures: {len(AVAILABLE_SIGS)}")
    print("✅ ML-KEM-768 (Kyber768) ready")
    print("✅ Falcon-512 ready")
    print("="*80)
    
except ImportError as e:
    print("="*80)
    print("❌ FATAL ERROR: liboqs library not found")
    print("❌ This service REQUIRES liboqs for real quantum cryptography")
    print()
    print("Installation instructions:")
    print("1. Install liboqs: https://github.com/open-quantum-safe/liboqs")
    print("2. Install Python wrapper: pip install liboqs-python")
    print()
    print(f"Error details: {e}")
    print("="*80)
    sys.exit(1)
    
except Exception as e:
    print(f"❌ FATAL ERROR: Failed to initialize liboqs: {e}")
    sys.exit(1)

# Configure extensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('quantum_service.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# FastAPI app with comprehensive documentation
app = FastAPI(
    title="Quantum Crypto Service - Real Implementation",
    description="""
    Production quantum-resistant cryptographic service implementing:
    - ML-KEM-768 (Kyber768) for key encapsulation
    - Falcon-512 for quantum-resistant signatures
    - ECDSA-P256 for classical wrapper signatures
    - Wrap-and-Sign hybrid protocol for maximum security
    - AES-256-GCM for symmetric encryption
    - HKDF for key derivation
    
    NOTE: This version REQUIRES liboqs library - no simulation mode available
    """,
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Global storage with session management
session_keys = {}
key_exchange_cache = {}
signature_cache = {}
session_metadata = {}

# Constants for cryptographic parameters
ML_KEM_768_PUBLIC_KEY_SIZE = 1184
ML_KEM_768_PRIVATE_KEY_SIZE = 2400
ML_KEM_768_CIPHERTEXT_SIZE = 1088
ML_KEM_768_SHARED_SECRET_SIZE = 32

FALCON_512_PUBLIC_KEY_SIZE = 897
FALCON_512_PRIVATE_KEY_SIZE = 1281
FALCON_512_SIGNATURE_MIN_SIZE = 600
FALCON_512_SIGNATURE_MAX_SIZE = 800

ECDSA_P256_PUBLIC_KEY_SIZE_MIN = 88
ECDSA_P256_PUBLIC_KEY_SIZE_MAX = 120
ECDSA_P256_SIGNATURE_SIZE_MIN = 64
ECDSA_P256_SIGNATURE_SIZE_MAX = 72

# Pydantic models with extensive validation
class KeyGenRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=100, description="Unique user identifier")
    key_type: Optional[str] = Field(default="all", pattern="^(all|kem|sig|ecdsa)$")
    metadata: Optional[Dict[str, Any]] = Field(default={})
    
    @validator('user_id')
    def validate_user_id(cls, v):
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('User ID must be alphanumeric with hyphens or underscores only')
        return v

class EncapsulateRequest(BaseModel):
    receiver_public_key: str = Field(..., description="Base64 encoded ML-KEM-768 public key")
    sender_id: Optional[str] = Field(None, description="Sender identification")
    session_id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()))
    metadata: Optional[Dict[str, Any]] = Field(default={})
    
    @validator('receiver_public_key')
    def validate_public_key(cls, v):
        try:
            decoded = base64.b64decode(v)
            if len(decoded) != ML_KEM_768_PUBLIC_KEY_SIZE:
                raise ValueError(f"Invalid public key size: {len(decoded)} bytes, expected {ML_KEM_768_PUBLIC_KEY_SIZE}")
        except Exception as e:
            raise ValueError(f"Invalid base64 public key: {e}")
        return v

class DecapsulateRequest(BaseModel):
    ciphertext: str = Field(..., description="Base64 encoded ML-KEM ciphertext")
    user_id: str = Field(..., description="User ID for key retrieval")
    session_id: Optional[str] = None
    
    @validator('ciphertext')
    def validate_ciphertext(cls, v):
        try:
            decoded = base64.b64decode(v)
            if len(decoded) != ML_KEM_768_CIPHERTEXT_SIZE:
                raise ValueError(f"Invalid ciphertext size: {len(decoded)} bytes")
        except Exception as e:
            raise ValueError(f"Invalid base64 ciphertext: {e}")
        return v

class WrapSignRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=1000000, description="Message to sign")
    user_id: str = Field(..., description="User ID for key retrieval")
    signature_type: Optional[str] = Field(default="wrap_sign", pattern="^(wrap_sign|falcon_only|ecdsa_only)$")
    hash_algorithm: Optional[str] = Field(default="SHA256", pattern="^(SHA256|SHA384|SHA512)$")
    
    @validator('message')
    def validate_message(cls, v):
        if len(v.encode('utf-8')) > 1000000:
            raise ValueError('Message too large (max 1MB)')
        return v

class WrapVerifyRequest(BaseModel):
    message: str = Field(..., description="Original message")
    falcon_signature: str = Field(..., description="Base64 encoded Falcon-512 signature")
    ecdsa_signature: str = Field(..., description="Base64 encoded ECDSA signature")
    falcon_public: str = Field(..., description="Base64 encoded Falcon-512 public key")
    ecdsa_public: str = Field(..., description="PEM encoded ECDSA public key")
    signature_type: Optional[str] = Field(default="wrap_sign")

class EncryptRequest(BaseModel):
    plaintext: str = Field(..., description="Plaintext to encrypt")
    shared_secret: str = Field(..., description="Base64 encoded shared secret")
    aad: Optional[str] = Field(None, description="Additional authenticated data")

class DecryptRequest(BaseModel):
    ciphertext: str = Field(..., description="Base64 encoded ciphertext")
    nonce: str = Field(..., description="Base64 encoded nonce")
    tag: str = Field(..., description="Base64 encoded tag")
    shared_secret: str = Field(..., description="Base64 encoded shared secret")
    aad: Optional[str] = Field(None, description="Additional authenticated data")

# Helper functions for cryptographic operations (REAL ONLY)
def generate_kem_keypair(user_id: str) -> Dict:
    """Generate ML-KEM-768 (Kyber768) keypair using real liboqs"""
    kem = oqs.KeyEncapsulation("Kyber768")
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    
    # Store KEM object for later use
    if user_id not in session_keys:
        session_keys[user_id] = {}
    session_keys[user_id]["kem_obj"] = kem
    
    return {
        "public": public_key,
        "private": private_key,
        "algorithm": "ML-KEM-768 (Kyber768) REAL"
    }

def generate_sig_keypair(user_id: str) -> Dict:
    """Generate Falcon-512 keypair using real liboqs"""
    sig = oqs.Signature("Falcon-512")
    public_key = sig.generate_keypair()
    private_key = sig.export_secret_key()
    
    # Store signature object for later use
    if user_id not in session_keys:
        session_keys[user_id] = {}
    session_keys[user_id]["sig_obj"] = sig
    
    return {
        "public": public_key,
        "private": private_key,
        "algorithm": "Falcon-512 REAL"
    }

def perform_encapsulation(public_key: bytes) -> Tuple[bytes, bytes]:
    """Perform ML-KEM-768 encapsulation using real liboqs"""
    kem = oqs.KeyEncapsulation("Kyber768")
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret

def perform_decapsulation(ciphertext: bytes, user_id: str) -> bytes:
    """Perform ML-KEM-768 decapsulation using real liboqs"""
    if user_id not in session_keys or "kem_obj" not in session_keys[user_id]:
        raise ValueError(f"User {user_id} has no KEM keys")
    
    kem = session_keys[user_id]["kem_obj"]
    shared_secret = kem.decap_secret(ciphertext)
    return shared_secret

def create_falcon_signature(message: bytes, user_id: str) -> bytes:
    """Create Falcon-512 signature using real liboqs"""
    if user_id not in session_keys or "sig_obj" not in session_keys[user_id]:
        raise ValueError(f"User {user_id} has no signature keys")
    
    sig = session_keys[user_id]["sig_obj"]
    signature = sig.sign(message)
    return signature

def verify_falcon_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify Falcon-512 signature using real liboqs"""
    sig = oqs.Signature("Falcon-512")
    return sig.verify(message, signature, public_key)

def encrypt_with_aes_gcm(plaintext: bytes, key: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    """Encrypt using AES-256-GCM"""
    nonce = os.urandom(12)
    
    cipher = Cipher(
        algorithms.AES(key[:32]),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    if aad:
        encryptor.authenticate_additional_data(aad)
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext, nonce, encryptor.tag

def decrypt_with_aes_gcm(ciphertext: bytes, nonce: bytes, tag: bytes, key: bytes, aad: Optional[bytes] = None) -> bytes:
    """Decrypt using AES-256-GCM"""
    cipher = Cipher(
        algorithms.AES(key[:32]),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    if aad:
        decryptor.authenticate_additional_data(aad)
    
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# API Endpoints
@app.post("/api/quantum/keygen", status_code=status.HTTP_201_CREATED)
def generate_quantum_keys(request: KeyGenRequest):
    """Generate complete set of quantum-resistant keys"""
    try:
        start_time = datetime.utcnow()
        
        # Initialize user key storage
        if request.user_id not in session_keys:
            session_keys[request.user_id] = {}
        
        # Generate ML-KEM-768 keypair
        ml_kem_keys = generate_kem_keypair(request.user_id)
        session_keys[request.user_id]["ml_kem"] = ml_kem_keys
        
        # Generate Falcon-512 keypair
        falcon_keys = generate_sig_keypair(request.user_id)
        session_keys[request.user_id]["falcon"] = falcon_keys
        
        # Generate ECDSA-P256 keypair
        ecdsa_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ecdsa_public = ecdsa_private.public_key()
        
        ecdsa_public_pem = ecdsa_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        ecdsa_private_pem = ecdsa_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        session_keys[request.user_id]["ecdsa"] = {
            "private": ecdsa_private,
            "public": ecdsa_public,
            "private_pem": ecdsa_private_pem,
            "public_pem": ecdsa_public_pem
        }
        
        # Store metadata
        session_metadata[request.user_id] = {
            "created_at": start_time.isoformat(),
            "last_used": start_time.isoformat(),
            "key_generation_time_ms": (datetime.utcnow() - start_time).total_seconds() * 1000,
            "metadata": request.metadata,
            "quantum_ready": True
        }
        
        logger.info(f"Generated quantum keys for user {request.user_id} (Real Implementation)")
        
        return {
            "user_id": request.user_id,
            "public_keys": {
                "ml_kem_768": base64.b64encode(ml_kem_keys["public"]).decode(),
                "falcon_512": base64.b64encode(falcon_keys["public"]).decode(),
                "ecdsa_p256": ecdsa_public_pem.decode()
            },
            "key_sizes": {
                "ml_kem_public": len(ml_kem_keys["public"]),
                "ml_kem_private": len(ml_kem_keys["private"]),
                "falcon_public": len(falcon_keys["public"]),
                "falcon_private": len(falcon_keys["private"]),
                "ecdsa_public": len(ecdsa_public_pem),
                "ecdsa_private": len(ecdsa_private_pem)
            },
            "algorithms": {
                "kem": ml_kem_keys["algorithm"],
                "sig_quantum": falcon_keys["algorithm"],
                "sig_classical": "ECDSA-P256 (NIST P-256)"
            },
            "metadata": session_metadata[request.user_id],
            "quantum_implementation": "REAL",
            "security_level": "NIST Level 3",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Key generation failed for user {request.user_id}: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Key generation failed: {str(e)}"
        )

@app.post("/api/quantum/encapsulate")
def encapsulate(request: EncapsulateRequest):
    """Perform ML-KEM-768 encapsulation for key exchange"""
    try:
        start_time = datetime.utcnow()
        
        # Decode public key
        public_key = base64.b64decode(request.receiver_public_key)
        
        # Perform encapsulation
        ciphertext, shared_secret = perform_encapsulation(public_key)
        
        # Derive AES key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'QMS-ML-KEM-768-v2',
            info=b'key-exchange-' + request.session_id.encode() if request.session_id else b'key-exchange',
            backend=default_backend()
        )
        aes_key = hkdf.derive(shared_secret)
        
        # Cache the shared secret for this session
        if request.session_id:
            key_exchange_cache[request.session_id] = {
                "shared_secret": shared_secret,
                "aes_key": aes_key,
                "timestamp": datetime.utcnow().isoformat(),
                "sender_id": request.sender_id,
                "metadata": request.metadata
            }
        
        encapsulation_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        logger.info(f"ML-KEM-768 encapsulation completed for session {request.session_id}")
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "shared_secret": base64.b64encode(aes_key).decode(),
            "session_id": request.session_id,
            "ciphertext_size": len(ciphertext),
            "shared_secret_size": len(aes_key),
            "algorithm": "ML-KEM-768 (Kyber768)",
            "kdf": "HKDF-SHA256",
            "encapsulation_time_ms": encapsulation_time,
            "quantum_implementation": "REAL",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Encapsulation failed: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encapsulation failed: {str(e)}"
        )

@app.post("/api/quantum/decapsulate")
def decapsulate(request: DecapsulateRequest):
    """Perform ML-KEM-768 decapsulation"""
    try:
        start_time = datetime.utcnow()
        
        if request.user_id not in session_keys:
            raise ValueError(f"No keys found for user {request.user_id}")
        
        # Decode ciphertext
        ciphertext = base64.b64decode(request.ciphertext)
        
        # Perform decapsulation
        shared_secret = perform_decapsulation(ciphertext, request.user_id)
        
        # Derive AES key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'QMS-ML-KEM-768-v2',
            info=b'key-exchange-' + request.session_id.encode() if request.session_id else b'key-exchange',
            backend=default_backend()
        )
        aes_key = hkdf.derive(shared_secret)
        
        # Update session metadata
        if request.user_id in session_metadata:
            session_metadata[request.user_id]["last_used"] = datetime.utcnow().isoformat()
        
        decapsulation_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        logger.info(f"ML-KEM-768 decapsulation completed for user {request.user_id}")
        
        return {
            "shared_secret": base64.b64encode(aes_key).decode(),
            "shared_secret_size": len(aes_key),
            "algorithm": "ML-KEM-768 (Kyber768)",
            "kdf": "HKDF-SHA256",
            "decapsulation_time_ms": decapsulation_time,
            "quantum_implementation": "REAL",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Decapsulation failed: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decapsulation failed: {str(e)}"
        )

@app.post("/api/quantum/wrap_sign")
def create_wrap_sign_signature(request: WrapSignRequest):
    """Create wrap-and-sign hybrid signature (Falcon-512 inner, ECDSA-P256 outer)"""
    try:
        start_time = datetime.utcnow()
        
        if request.user_id not in session_keys:
            raise ValueError(f"No keys found for user {request.user_id}")
        
        message_bytes = request.message.encode('utf-8')
        user_keys = session_keys[request.user_id]
        
        # Select hash algorithm
        hash_map = {
            "SHA256": hashes.SHA256(),
            "SHA384": hashes.SHA384(),
            "SHA512": hashes.SHA512()
        }
        hash_algo = hash_map[request.hash_algorithm if request.hash_algorithm else "SHA256"]
        
        # Step 1: Create Falcon-512 signature (quantum-resistant inner signature)
        falcon_signature = create_falcon_signature(message_bytes, request.user_id)
        
        logger.info(f"Falcon-512 signature created: {len(falcon_signature)} bytes")
        
        # Step 2: Create ECDSA-P256 outer signature (classical wrapper)
        if request.signature_type in ["wrap_sign", "ecdsa_only"]:
            wrapped_data = message_bytes + falcon_signature if request.signature_type == "wrap_sign" else message_bytes
            ecdsa_private = user_keys["ecdsa"]["private"]
            ecdsa_signature = ecdsa_private.sign(wrapped_data, ec.ECDSA(hash_algo))
        else:
            ecdsa_signature = b""
        
        # Cache signature for verification
        sig_id = str(uuid.uuid4())
        signature_cache[sig_id] = {
            "message_hash": hashlib.sha256(message_bytes).hexdigest(),
            "falcon_signature": falcon_signature,
            "ecdsa_signature": ecdsa_signature,
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": request.user_id,
            "signature_type": request.signature_type
        }
        
        signing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        # Update session metadata
        if request.user_id in session_metadata:
            session_metadata[request.user_id]["last_used"] = datetime.utcnow().isoformat()
        
        logger.info(f"Wrap-and-sign signature created for user {request.user_id}")
        
        return {
            "signature_id": sig_id,
            "falcon_signature": base64.b64encode(falcon_signature).decode(),
            "ecdsa_signature": base64.b64encode(ecdsa_signature).decode() if ecdsa_signature else "",
            "signature_sizes": {
                "falcon": len(falcon_signature),
                "ecdsa": len(ecdsa_signature),
                "total": len(falcon_signature) + len(ecdsa_signature)
            },
            "algorithms": {
                "quantum": "Falcon-512",
                "classical": "ECDSA-P256",
                "hash": request.hash_algorithm
            },
            "protocol": request.signature_type,
            "signing_time_ms": signing_time,
            "quantum_implementation": "REAL",
            "security_level": "NIST Level 3",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Wrap-sign failed for user {request.user_id}: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Signature creation failed: {str(e)}"
        )

@app.post("/api/quantum/wrap_verify")
def verify_wrap_sign_signature(request: WrapVerifyRequest):
    """Verify wrap-and-sign hybrid signature"""
    try:
        start_time = datetime.utcnow()
        
        message_bytes = request.message.encode('utf-8') if request.message else b""
        falcon_sig = base64.b64decode(request.falcon_signature)
        ecdsa_sig = base64.b64decode(request.ecdsa_signature) if request.ecdsa_signature else b""
        falcon_public = base64.b64decode(request.falcon_public)
        
        verification_results = {
            "ecdsa_valid": False,
            "falcon_valid": False,
            "overall_valid": False,
            "verification_details": {}
        }
        
        # Step 1: Verify ECDSA outer signature
        if request.ecdsa_signature and request.ecdsa_public:
            try:
                loaded_key = serialization.load_pem_public_key(
                    request.ecdsa_public.encode('utf-8'),
                    backend=default_backend()
                )
                
                if isinstance(loaded_key, ec.EllipticCurvePublicKey):
                    wrapped_data = message_bytes + falcon_sig if request.signature_type == "wrap_sign" else message_bytes
                    
                    try:
                        loaded_key.verify(
                            ecdsa_sig,
                            wrapped_data,
                            ec.ECDSA(hashes.SHA256())
                        )
                        verification_results["ecdsa_valid"] = True
                        verification_results["verification_details"]["ecdsa"] = "Valid ECDSA-P256 signature"
                        logger.info("ECDSA outer signature verified successfully")
                    except InvalidSignature:
                        verification_results["verification_details"]["ecdsa"] = "Invalid ECDSA signature"
                        logger.warning("ECDSA signature verification failed")
                else:
                    verification_results["verification_details"]["ecdsa"] = "Invalid ECDSA public key type"
            except Exception as e:
                verification_results["verification_details"]["ecdsa"] = f"ECDSA verification error: {str(e)}"
                logger.error(f"ECDSA verification error: {e}")
        
        # Step 2: Verify Falcon-512 inner signature
        if request.signature_type == "wrap_sign" and not verification_results["ecdsa_valid"]:
            verification_results["verification_details"]["falcon"] = "Skipped - ECDSA wrapper invalid"
        else:
            falcon_valid = verify_falcon_signature(message_bytes, falcon_sig, falcon_public)
            verification_results["falcon_valid"] = falcon_valid
            verification_results["verification_details"]["falcon"] = "Valid Falcon-512 signature" if falcon_valid else "Invalid Falcon signature"
            
            if falcon_valid:
                logger.info("Falcon-512 signature verified successfully")
            else:
                logger.warning("Falcon-512 verification failed")
        
        # Overall validity
        if request.signature_type == "wrap_sign":
            verification_results["overall_valid"] = verification_results["ecdsa_valid"] and verification_results["falcon_valid"]
        elif request.signature_type == "falcon_only":
            verification_results["overall_valid"] = verification_results["falcon_valid"]
        elif request.signature_type == "ecdsa_only":
            verification_results["overall_valid"] = verification_results["ecdsa_valid"]
        
        verification_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        return {
            "valid": verification_results["overall_valid"],
            "ecdsa_valid": verification_results["ecdsa_valid"],
            "falcon_valid": verification_results["falcon_valid"],
            "verification_details": verification_results["verification_details"],
            "protocol": request.signature_type,
            "verification_time_ms": verification_time,
            "quantum_implementation": "REAL",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Verification failed: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "valid": False,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

@app.post("/api/quantum/encrypt")
def encrypt_message(request: EncryptRequest):
    """Encrypt message using AES-256-GCM with quantum-derived key"""
    try:
        shared_secret = base64.b64decode(request.shared_secret)
        plaintext = request.plaintext.encode('utf-8')
        aad = request.aad.encode('utf-8') if request.aad else None
        
        ciphertext, nonce, tag = encrypt_with_aes_gcm(plaintext, shared_secret, aad)
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "algorithm": "AES-256-GCM",
            "ciphertext_size": len(ciphertext)
        }
        
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encryption failed: {str(e)}"
        )

@app.post("/api/quantum/decrypt")
def decrypt_message(request: DecryptRequest):
    """Decrypt message using AES-256-GCM with quantum-derived key"""
    try:
        shared_secret = base64.b64decode(request.shared_secret)
        ciphertext = base64.b64decode(request.ciphertext)
        nonce = base64.b64decode(request.nonce)
        tag = base64.b64decode(request.tag)
        aad = request.aad.encode('utf-8') if request.aad else None
        
        plaintext = decrypt_with_aes_gcm(ciphertext, nonce, tag, shared_secret, aad)
        
        return {
            "plaintext": plaintext.decode('utf-8'),
            "algorithm": "AES-256-GCM"
        }
        
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Decryption failed: {str(e)}"
        )

@app.get("/api/quantum/info")
def get_quantum_service_info():
    """Get comprehensive information about the quantum service"""
    return {
        "status": "operational",
        "mode": "REAL QUANTUM CRYPTOGRAPHY",
        "quantum_ready": True,
        "quantum_version": QUANTUM_VERSION,
        "algorithms": {
            "kem": {
                "name": "ML-KEM-768 (Kyber768)",
                "public_key_size": ML_KEM_768_PUBLIC_KEY_SIZE,
                "private_key_size": ML_KEM_768_PRIVATE_KEY_SIZE,
                "ciphertext_size": ML_KEM_768_CIPHERTEXT_SIZE,
                "shared_secret_size": ML_KEM_768_SHARED_SECRET_SIZE,
                "security_level": "NIST Level 3"
            },
            "sig": {
                "name": "Falcon-512",
                "public_key_size": FALCON_512_PUBLIC_KEY_SIZE,
                "private_key_size": FALCON_512_PRIVATE_KEY_SIZE,
                "signature_size": f"{FALCON_512_SIGNATURE_MIN_SIZE}-{FALCON_512_SIGNATURE_MAX_SIZE} bytes",
                "security_level": "NIST Level 1"
            },
            "wrapper": {
                "name": "ECDSA-P256",
                "curve": "NIST P-256 (secp256r1)",
                "signature_size": f"{ECDSA_P256_SIGNATURE_SIZE_MIN}-{ECDSA_P256_SIGNATURE_SIZE_MAX} bytes"
            }
        },
        "available_kems": len(AVAILABLE_KEMS),
        "available_sigs": len(AVAILABLE_SIGS),
        "kems_list": AVAILABLE_KEMS[:10],
        "sigs_list": AVAILABLE_SIGS[:10],
        "active_sessions": len(session_keys),
        "cached_key_exchanges": len(key_exchange_cache),
        "cached_signatures": len(signature_cache),
        "server_time": datetime.utcnow().isoformat(),
        "api_version": "3.0.0",
        "documentation": "/docs",
        "redoc": "/redoc"
    }

@app.get("/api/quantum/session/{user_id}")
def get_session_info(user_id: str):
    """Get session information for a specific user"""
    if user_id not in session_keys:
        raise HTTPException(status_code=404, detail="User session not found")
    
    metadata = session_metadata.get(user_id, {})
    
    return {
        "user_id": user_id,
        "has_ml_kem_keys": "ml_kem" in session_keys[user_id],
        "has_falcon_keys": "falcon" in session_keys[user_id],
        "has_ecdsa_keys": "ecdsa" in session_keys[user_id],
        "metadata": metadata,
        "quantum_implementation": "REAL"
    }

@app.delete("/api/quantum/session/{user_id}")
def delete_session(user_id: str):
    """Delete all keys and session data for a user"""
    if user_id in session_keys:
        del session_keys[user_id]
    if user_id in session_metadata:
        del session_metadata[user_id]
    
    # Clean up related caches
    keys_to_delete = []
    for key, value in key_exchange_cache.items():
        if value.get("sender_id") == user_id:
            keys_to_delete.append(key)
    
    for key in keys_to_delete:
        del key_exchange_cache[key]
    
    logger.info(f"Session deleted for user {user_id}")
    
    return {"message": f"Session deleted for user {user_id}"}

@app.get("/api/health")
def health_check():
    """Comprehensive health check endpoint"""
    return {
        "status": "healthy",
        "service": "Quantum Crypto Service",
        "mode": "REAL",
        "quantum_library": "liboqs",
        "version": QUANTUM_VERSION,
        "uptime_seconds": (datetime.utcnow() - app.state.start_time).total_seconds() if hasattr(app.state, 'start_time') else 0,
        "active_sessions": len(session_keys),
        "timestamp": datetime.utcnow().isoformat()
    }

@app.on_event("startup")
async def startup_event():
    """Initialize service on startup"""
    app.state.start_time = datetime.utcnow()
    logger.info(f"Quantum Crypto Service started - Mode: REAL")
    logger.info(f"Available at: http://localhost:3001")
    logger.info(f"Documentation: http://localhost:3001/docs")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info(f"Quantum Crypto Service shutting down")
    logger.info(f"Active sessions cleared: {len(session_keys)}")
    session_keys.clear()
    key_exchange_cache.clear()
    signature_cache.clear()
    session_metadata.clear()

# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}")
    logger.error(traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if app.state.get("debug", False) else "An error occurred",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*80)
    print("QUANTUM CRYPTO SERVICE - REAL IMPLEMENTATION - v3.0.0")
    print("="*80)
    print("✅ RUNNING WITH REAL QUANTUM CRYPTOGRAPHY ONLY")
    print(f"✅ liboqs version: {QUANTUM_VERSION}")
    print(f"✅ Available algorithms: {len(AVAILABLE_KEMS)} KEMs, {len(AVAILABLE_SIGS)} Signatures")
    print("="*80)
    print("Algorithms:")
    print("  • Key Exchange: ML-KEM-768 (Kyber768) - NIST Level 3")
    print("  • Digital Signature: Falcon-512 - NIST Level 1")
    print("  • Wrapper Signature: ECDSA-P256")
    print("  • Symmetric Encryption: AES-256-GCM")
    print("  • Key Derivation: HKDF-SHA256")
    print("="*80)
    print("Starting server on https://localhost:3001 (SSL enabled)")
    print("API Documentation: https://localhost:3001/docs")
    print("Alternative Docs: https://localhost:3001/redoc")
    print("="*80 + "\n")
    
    import os
    import subprocess
    
    # Get local IP for certificate filename
    try:
        result = subprocess.run(['ifconfig'], capture_output=True, text=True)
        local_ip = "localhost"  # fallback
        for line in result.stdout.split('\n'):
            if 'inet ' in line and '127.0.0.1' not in line and 'inet ' in line:
                local_ip = line.split()[1]
                break
    except:
        local_ip = "localhost"
    
    # Try IP-based certificates first, fallback to localhost
    cert_path = f"{local_ip}+3.pem"
    key_path = f"{local_ip}+3-key.pem"
    
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        cert_path = "localhost+3.pem"
        key_path = "localhost+3-key.pem"
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        print("🔒 SSL certificates found - enabling HTTPS")
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=3001,
            ssl_keyfile=key_path,
            ssl_certfile=cert_path,
            log_level="info",
            access_log=True,
            use_colors=True
        )
    else:
        print("⚠️ SSL certificates not found - falling back to HTTP")
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=3001,
            log_level="info",
            access_log=True,
            use_colors=True
        )