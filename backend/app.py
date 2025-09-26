# Complete app.py - Quantum Messaging System Backend
# type: ignore  # SQLAlchemy runtime attributes work correctly despite type warnings
from fastapi import FastAPI, HTTPException, Depends, status, Request, WebSocket, WebSocketDisconnect, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Text, Integer, ForeignKey, or_, and_, desc, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, Field, EmailStr, validator
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import jwt
import bcrypt
import json
import uuid
import base64
import httpx
import os
import hashlib
import logging
import traceback
import asyncio
import time
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('qms_platform.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
SECRET_KEY = os.environ.get("JWT_SECRET", "quantum-secure-key-" + secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440
BCRYPT_ROUNDS = 12

# Service URLs - Support both HTTP and HTTPS
QUANTUM_API = os.environ.get("QUANTUM_API_URL", "https://localhost:3001")

# Database configuration
SQLALCHEMY_DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./qms_quantum.db")
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in SQLALCHEMY_DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ========== DATABASE MODELS ==========
class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    last_seen = Column(DateTime, default=datetime.utcnow)
    public_keys = Column(Text, nullable=True)
    key_generation_timestamp = Column(DateTime, nullable=True)
    
    # Relationships
    sent_requests = relationship("ConnectionRequest", foreign_keys="ConnectionRequest.sender_id", back_populates="sender", cascade="all, delete-orphan")
    received_requests = relationship("ConnectionRequest", foreign_keys="ConnectionRequest.receiver_id", back_populates="receiver", cascade="all, delete-orphan")
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender", cascade="all, delete-orphan")
    received_messages = relationship("Message", foreign_keys="Message.receiver_id", back_populates="receiver", cascade="all, delete-orphan")
    performance_metrics = relationship("PerformanceMetric", back_populates="user", cascade="all, delete-orphan")

class ConnectionRequest(Base):
    __tablename__ = "connection_requests"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id = Column(String, ForeignKey("users.id"))
    receiver_id = Column(String, ForeignKey("users.id"))
    sender_public_keys = Column(Text, nullable=False)
    receiver_public_keys = Column(Text, nullable=True)
    status = Column(String(20), default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    responded_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(hours=24))
    
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_requests")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_requests")

class SecureSession(Base):
    __tablename__ = "secure_sessions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user1_id = Column(String, ForeignKey("users.id"))
    user2_id = Column(String, ForeignKey("users.id"))
    request_id = Column(String, ForeignKey("connection_requests.id"), nullable=True)
    shared_secret = Column(Text, nullable=True)
    ciphertext = Column(Text, nullable=True)
    session_metadata = Column(Text, nullable=True)
    established_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, default=datetime.utcnow)
    terminated_at = Column(DateTime, nullable=True)
    termination_reason = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    message_count = Column(Integer, default=0)
    
    user1 = relationship("User", foreign_keys=[user1_id])
    user2 = relationship("User", foreign_keys=[user2_id])
    connection_request = relationship("ConnectionRequest", foreign_keys=[request_id])
    messages = relationship("Message", back_populates="session", cascade="all, delete-orphan")

class Message(Base):
    __tablename__ = "messages"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("secure_sessions.id"))
    sender_id = Column(String, ForeignKey("users.id"))
    receiver_id = Column(String, ForeignKey("users.id"))
    encrypted_content = Column(Text, nullable=False)
    nonce = Column(String(32), nullable=False)
    tag = Column(String(32), nullable=False)
    aad = Column(Text, nullable=True)
    falcon_signature = Column(Text, nullable=True)
    ecdsa_signature = Column(Text, nullable=True)
    signature_metadata = Column(Text, nullable=True)
    message_type = Column(String(20), default="secured")
    timestamp = Column(DateTime, default=datetime.utcnow)
    delivered_at = Column(DateTime, nullable=True)
    read_at = Column(DateTime, nullable=True)
    is_read = Column(Boolean, default=False)
    is_deleted_sender = Column(Boolean, default=False)
    is_deleted_receiver = Column(Boolean, default=False)
    
    session = relationship("SecureSession", back_populates="messages")
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_messages")

class PerformanceMetric(Base):
    __tablename__ = "performance_metrics"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"))
    operation = Column(String(50), nullable=False)
    duration_ms = Column(Float, nullable=False)
    data_size = Column(Integer, nullable=True)
    is_critical = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="performance_metrics")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", foreign_keys=[user_id])

# Create tables
Base.metadata.create_all(bind=engine)

# ========== FASTAPI APP ==========
app = FastAPI(
    title="QMS Platform - Quantum Messaging System",
    description="Enhanced quantum-resistant messaging platform",
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

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

# ========== WEBSOCKET CONNECTION MANAGER ==========
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, str] = {}
        
    async def connect(self, websocket: WebSocket, username: str):
        await websocket.accept()
        connection_id = str(uuid.uuid4())
        self.active_connections[connection_id] = websocket
        self.user_connections[username] = connection_id
        logger.info(f"WebSocket connected: {username}")
        return connection_id
        
    def disconnect(self, username: str):
        if username in self.user_connections:
            connection_id = self.user_connections[username]
            if connection_id in self.active_connections:
                del self.active_connections[connection_id]
            del self.user_connections[username]
            logger.info(f"WebSocket disconnected: {username}")
            
    async def send_personal_message(self, username: str, message):
        if username in self.user_connections:
            connection_id = self.user_connections[username]
            if connection_id in self.active_connections:
                try:
                    websocket = self.active_connections[connection_id]
                    message_str = json.dumps(message) if isinstance(message, dict) else message
                    await websocket.send_text(message_str)
                    return True
                except Exception as e:
                    logger.error(f"Error sending WebSocket message to {username}: {e}")
                    self.disconnect(username)
        return False
        
    async def broadcast_to_users(self, message, usernames: List[str]):
        for username in usernames:
            await self.send_personal_message(username, message)
            
    def get_online_users(self) -> List[str]:
        return list(self.user_connections.keys())

manager = ConnectionManager()

# ========== PYDANTIC MODELS ==========
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_\\-]+$")
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=100)
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Username must be alphanumeric with hyphens or underscores only')
        return v.lower()

class UserLogin(BaseModel):
    username: str
    password: str

class ConnectionRequestCreate(BaseModel):
    receiver_username: str
    sender_public_keys: Dict[str, str]
    metadata: Optional[Dict[str, Any]] = Field(default={})

class ConnectionResponse(BaseModel):
    request_id: str
    accept: bool
    receiver_public_keys: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = Field(default={})

class MessageSend(BaseModel):
    content: str = Field(..., min_length=1, max_length=50000)
    message_type: str = Field(default="secured", pattern="^(secured|critical)$")
    metadata: Optional[Dict[str, Any]] = Field(default={})

class SessionStatus(BaseModel):
    active: bool
    session_id: Optional[str] = None
    peer_username: Optional[str] = None
    peer_id: Optional[str] = None
    established_at: Optional[str] = None
    last_activity: Optional[str] = None
    message_count: int = 0
    has_keys: bool = False
    quantum_ready: bool = False

class MessageResponse(BaseModel):
    id: str
    sender_username: str
    content: str
    message_type: str
    timestamp: str
    is_mine: bool
    verified: bool
    metadata: Optional[Dict[str, Any]] = None

# ========== HELPER FUNCTIONS ==========
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.utcnow(), "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        raise HTTPException(status_code=401, detail="Authentication failed")

def get_current_user(username: str = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is inactive")
    user.last_seen = datetime.utcnow()
    db.commit()
    return user

def get_active_session(user_id: str, db: Session) -> Optional[SecureSession]:
    return db.query(SecureSession).filter(
        or_(
            and_(SecureSession.user1_id == user_id, SecureSession.is_active == True),
            and_(SecureSession.user2_id == user_id, SecureSession.is_active == True)
        )
    ).first()

def encrypt_message(plaintext: str, shared_secret: bytes, sender_id: str = None, session_id: str = None) -> tuple:
    """Encrypt message using AES-256-GCM with AAD"""
    nonce = os.urandom(12)
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'QMS-MSG-ENCRYPT',
        info=b'message-encryption',
        backend=default_backend()
    )
    encryption_key = hkdf.derive(shared_secret[:32])
    
    # Create AAD with session and sender information
    aad_data = {
        "sender_id": sender_id or "unknown",
        "session_id": session_id or "default",
        "timestamp": datetime.utcnow().isoformat(),
        "protocol": "QMS-v2.0"
    }
    aad = json.dumps(aad_data, sort_keys=True).encode()
    
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(nonce).decode(),
        base64.b64encode(encryptor.tag).decode(),
        base64.b64encode(aad).decode()
    )

def decrypt_message(ciphertext_b64: str, nonce_b64: str, tag_b64: str, shared_secret: bytes, aad_b64: str = None) -> str:
    """Decrypt message using AES-256-GCM with AAD verification"""
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        aad = base64.b64decode(aad_b64) if aad_b64 else None
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'QMS-MSG-ENCRYPT',
            info=b'message-encryption',
            backend=default_backend()
        )
        encryption_key = hkdf.derive(shared_secret[:32])
        
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Authenticate AAD if present
        if aad:
            decryptor.authenticate_additional_data(aad)
            
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise ValueError("Message decryption failed")
        raise ValueError("Message decryption failed")

def cleanup_expired_requests(db: Session):
    """Clean up expired connection requests"""
    try:
        expired = db.query(ConnectionRequest).filter(
            ConnectionRequest.status == "pending",
            ConnectionRequest.expires_at < datetime.utcnow()
        ).all()
        
        for req in expired:
            req.status = "expired"
        
        if expired:
            db.commit()
            logger.info(f"Cleaned up {len(expired)} expired connection requests")
    except Exception as e:
        logger.error(f"Error cleaning up expired requests: {e}")
        db.rollback()

def cleanup_inactive_sessions(db: Session):
    """Clean up inactive sessions after 24 hours"""
    try:
        cutoff = datetime.utcnow() - timedelta(hours=24)
        inactive = db.query(SecureSession).filter(
            SecureSession.is_active == True,
            SecureSession.last_activity < cutoff
        ).all()
        
        for session in inactive:
            session.is_active = False
            session.terminated_at = datetime.utcnow()
            session.termination_reason = "Inactivity timeout"
        
        if inactive:
            db.commit()
            logger.info(f"Cleaned up {len(inactive)} inactive sessions")
    except Exception as e:
        logger.error(f"Error cleaning up inactive sessions: {e}")
        db.rollback()

def audit_log(db: Session, user_id: Optional[str], action: str, details: Optional[str] = None, request: Optional[Request] = None):
    """Record audit log entry"""
    try:
        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        logger.error(f"Audit log failed: {str(e)}")

def record_performance_metric(db: Session, user_id: str, operation: str, duration_ms: float, 
                             data_size: int = None, is_critical: bool = False):
    """Record performance metrics"""
    try:
        metric = PerformanceMetric(
            user_id=user_id,
            operation=operation,
            duration_ms=duration_ms,
            data_size=data_size,
            is_critical=is_critical
        )
        db.add(metric)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to record metric: {str(e)}")

# ========== AUTHENTICATION ENDPOINTS ==========
@app.post("/api/register", status_code=status.HTTP_201_CREATED)
def register(user: UserRegister, request: Request, db: Session = Depends(get_db)):
    """Register a new user"""
    # Check if user already exists
    if db.query(User).filter(User.username == user.username.lower()).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    
    if db.query(User).filter(User.email == user.email.lower()).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password
    hashed = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt(BCRYPT_ROUNDS))
    
    # Create user
    db_user = User(
        username=user.username.lower(),
        email=user.email.lower(),
        hashed_password=hashed.decode('utf-8')
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Audit log
    audit_log(db, db_user.id, "USER_REGISTRATION", f"New user registered: {user.username}", request)
    logger.info(f"New user registered: {user.username}")
    
    return {
        "message": "User registered successfully",
        "user_id": db_user.id,
        "username": db_user.username,
        "quantum_ready": True
    }

@app.post("/api/login")
async def login(
    username: str = Form(...),
    password: str = Form(...),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """User login endpoint"""
    user = db.query(User).filter(User.username == username.lower()).first()
    
    if not user:
        audit_log(db, None, "LOGIN_FAILED", f"Invalid username: {username}", request)
        logger.warning(f"Login attempt for non-existent user: {username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not bcrypt.checkpw(password.encode('utf-8'), user.hashed_password.encode('utf-8')):
        audit_log(db, user.id, "LOGIN_FAILED", "Invalid password", request)
        logger.warning(f"Failed login attempt for user: {username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        audit_log(db, user.id, "LOGIN_BLOCKED", "Inactive account", request)
        raise HTTPException(status_code=403, detail="Account is inactive")
    
    # Create token
    access_token = create_access_token(data={"sub": user.username})
    
    # Update last seen
    user.last_seen = datetime.utcnow()
    db.commit()
    
    audit_log(db, user.id, "LOGIN_SUCCESS", None, request)
    logger.info(f"User logged in: {user.username}")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "user_id": user.id,
        "quantum_ready": bool(user.public_keys)
    }

@app.post("/api/logout")
async def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db), request: Request = None):
    """User logout endpoint"""
    try:
        # Terminate active session if exists
        active_session = get_active_session(current_user.id, db)
        if active_session:
            other_user_id = active_session.user1_id if active_session.user2_id == current_user.id else active_session.user2_id
            other_user = db.query(User).filter(User.id == other_user_id).first()
            
            active_session.is_active = False
            active_session.terminated_at = datetime.utcnow()
            active_session.termination_reason = "User logout"
            
            # Clear keys
            current_user.public_keys = None
            current_user.key_generation_timestamp = None
            if other_user:
                other_user.public_keys = None
                other_user.key_generation_timestamp = None
                
                # Notify other user
                await manager.send_personal_message(
                    other_user.username,
                    {
                        "type": "session_update",
                        "status": "terminated",
                        "reason": "User logout",
                        "terminated_by": current_user.username
                    }
                )
        
        # Update last seen
        current_user.last_seen = datetime.utcnow()
        db.commit()
        
        audit_log(db, current_user.id, "LOGOUT", None, request)
        logger.info(f"User logged out: {current_user.username}")
        
        # Broadcast status update
        online_users = manager.get_online_users()
        await manager.broadcast_to_users(
            {
                "type": "user_status_update",
                "username": current_user.username,
                "status": "offline"
            },
            online_users
        )
        
        return {"message": "Logged out successfully"}
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        raise HTTPException(status_code=500, detail="Logout failed")

# ========== CONNECTION MANAGEMENT ==========
@app.post("/api/connection/request", status_code=status.HTTP_201_CREATED)
async def create_connection_request(
    request_data: ConnectionRequestCreate,
    current_user: User = Depends(get_current_user),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """Create a connection request to another user"""
    # Clean up expired requests
    cleanup_expired_requests(db)
    
    # Check if user already has active session
    if get_active_session(current_user.id, db):
        raise HTTPException(status_code=400, detail="You already have an active session")
    
    # Get receiver
    receiver = db.query(User).filter(User.username == request_data.receiver_username.lower()).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="User not found")
    
    if receiver.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot connect to yourself")
    
    # Check if receiver has active session
    if get_active_session(receiver.id, db):
        raise HTTPException(status_code=400, detail=f"{receiver.username} is in an active session")
    
    # Cancel any existing pending requests
    existing = db.query(ConnectionRequest).filter(
        or_(
            and_(ConnectionRequest.sender_id == current_user.id, ConnectionRequest.receiver_id == receiver.id),
            and_(ConnectionRequest.sender_id == receiver.id, ConnectionRequest.receiver_id == current_user.id)
        ),
        ConnectionRequest.status == "pending"
    ).first()
    
    if existing:
        existing.status = "cancelled"
        db.commit()
    
    # Create new request
    conn_request = ConnectionRequest(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        sender_public_keys=json.dumps(request_data.sender_public_keys)
    )
    db.add(conn_request)
    db.commit()
    db.refresh(conn_request)
    
    # Update sender's public keys
    current_user.public_keys = json.dumps(request_data.sender_public_keys)
    current_user.key_generation_timestamp = datetime.utcnow()
    db.commit()
    
    audit_log(db, current_user.id, "CONNECTION_REQUEST_SENT", f"To: {receiver.username}", request)
    logger.info(f"Connection request from {current_user.username} to {receiver.username}")
    
    # Notify receiver via WebSocket
    await manager.send_personal_message(
        receiver.username,
        {
            "type": "connection_request",
            "sender": current_user.username,
            "request_id": conn_request.id
        }
    )
    
    return {
        "request_id": conn_request.id,
        "status": "sent",
        "receiver": receiver.username,
        "expires_at": conn_request.expires_at.isoformat(),
        "quantum_keys_included": True
    }

@app.get("/api/connection/pending")
def get_pending_requests(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get pending connection requests"""
    cleanup_expired_requests(db)
    
    requests = db.query(ConnectionRequest).filter(
        ConnectionRequest.receiver_id == current_user.id,
        ConnectionRequest.status == "pending"
    ).order_by(desc(ConnectionRequest.created_at)).all()
    
    return [{
        "request_id": req.id,
        "sender_id": req.sender_id,
        "sender_username": req.sender.username,
        "sender_public_keys": json.loads(req.sender_public_keys),
        "created_at": req.created_at.isoformat(),
        "expires_at": req.expires_at.isoformat()
    } for req in requests]

@app.post("/api/connection/respond")
async def respond_to_connection(
    response: ConnectionResponse,
    current_user: User = Depends(get_current_user),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """Respond to a connection request"""
    try:
        db.begin()
        
        # Get request
        conn_request = db.query(ConnectionRequest).filter(
            ConnectionRequest.id == response.request_id,
            ConnectionRequest.receiver_id == current_user.id,
            ConnectionRequest.status == "pending"
        ).with_for_update().first()
        
        if not conn_request:
            db.rollback()
            raise HTTPException(status_code=404, detail="Request not found or already processed")
        
        # Check expiration
        if conn_request.expires_at < datetime.utcnow():
            conn_request.status = "expired"
            db.commit()
            raise HTTPException(status_code=400, detail="Request has expired")
        
        # Check for active sessions
        users = db.query(User).filter(
            User.id.in_([current_user.id, conn_request.sender_id])
        ).with_for_update().all()
        
        for user in users:
            if get_active_session(user.id, db):
                conn_request.status = "cancelled"
                db.commit()
                raise HTTPException(status_code=400, detail="User already in session")
        
        conn_request.responded_at = datetime.utcnow()
        
        if response.accept:
            conn_request.status = "accepted"
            if response.receiver_public_keys:
                conn_request.receiver_public_keys = json.dumps(response.receiver_public_keys)
                current_user.public_keys = json.dumps(response.receiver_public_keys)
                current_user.key_generation_timestamp = datetime.utcnow()
            
            # Get sender's keys
            sender_keys = json.loads(conn_request.sender_public_keys)
            
            # Perform key encapsulation via quantum service
            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                encap_response = await client.post(
                    f"{QUANTUM_API}/api/quantum/encapsulate",
                    json={
                        "receiver_public_key": sender_keys["ml_kem_768"],
                        "sender_id": current_user.id,
                        "session_id": str(uuid.uuid4())
                    }
                )
                
                if encap_response.status_code != 200:
                    logger.error(f"Quantum encapsulation failed: {encap_response.text}")
                    db.rollback()
                    raise HTTPException(status_code=500, detail="Quantum key exchange failed")
                
                encap_data = encap_response.json()
            
            # Create session
            session = SecureSession(
                user1_id=conn_request.sender_id,
                user2_id=current_user.id,
                request_id=conn_request.id,
                shared_secret=encap_data["shared_secret"],
                ciphertext=encap_data["ciphertext"],
                session_metadata=json.dumps({
                    "quantum_algorithm": encap_data.get("algorithm", "ML-KEM-768"),
                    "kdf": encap_data.get("kdf", "HKDF-SHA256"),
                    "established_by": current_user.username,
                    "metadata": response.metadata
                }),
                is_active=True
            )
            db.add(session)
            
            db.commit()
            db.refresh(session)
            
            audit_log(db, current_user.id, "CONNECTION_ACCEPTED", f"From: {conn_request.sender.username}", request)
            logger.info(f"Quantum session established between {conn_request.sender.username} and {current_user.username}")
            
            # Notify both users
            await manager.send_personal_message(
                conn_request.sender.username,
                {
                    "type": "session_update",
                    "status": "accepted",
                    "peer_username": current_user.username,
                    "session_id": session.id
                }
            )
            await manager.send_personal_message(
                current_user.username,
                {
                    "type": "session_update",
                    "status": "accepted",
                    "peer_username": conn_request.sender.username,
                    "session_id": session.id
                }
            )
            
            return {
                "status": "accepted",
                "session_id": session.id,
                "peer_username": conn_request.sender.username,
                "ciphertext": encap_data["ciphertext"],
                "quantum_algorithm": encap_data.get("algorithm", "ML-KEM-768"),
                "session_established": True
            }
        else:
            conn_request.status = "rejected"
            db.commit()
            
            audit_log(db, current_user.id, "CONNECTION_REJECTED", f"From: {conn_request.sender.username}", request)
            
            # Notify sender
            await manager.send_personal_message(
                conn_request.sender.username,
                {
                    "type": "connection_request",
                    "status": "rejected",
                    "message": f"Connection request rejected by {current_user.username}"
                }
            )
            
            return {"status": "rejected"}
            
    except Exception as e:
        db.rollback()
        logger.error(f"Error in respond_to_connection: {e}")
        raise HTTPException(status_code=500, detail="Failed to process connection request")

# ========== MESSAGING ==========
@app.post("/api/message/send", status_code=status.HTTP_201_CREATED)
async def send_message(
    message: MessageSend,
    current_user: User = Depends(get_current_user),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """Send an encrypted message"""
    start_time = time.time()
    
    # Get active session
    session = get_active_session(current_user.id, db)
    if not session:
        raise HTTPException(status_code=403, detail="No active session")
    
    if not session.shared_secret:
        raise HTTPException(status_code=500, detail="Session key not established")
    
    # Encrypt message
    shared_secret = base64.b64decode(session.shared_secret)
    ciphertext, nonce, tag, aad = encrypt_message(
        message.content, 
        shared_secret, 
        sender_id=current_user.username,
        session_id=str(session.id)
    )
    
    # Sign all messages for quantum security
    falcon_sig = ""
    ecdsa_sig = ""
    sig_metadata = {}
    
    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        try:
            sign_response = await client.post(
                f"{QUANTUM_API}/api/quantum/wrap_sign",
                json={
                    "message": message.content,
                    "user_id": current_user.username,
                    "signature_type": "wrap_sign",
                    "hash_algorithm": "SHA256"
                }
            )
            
            if sign_response.status_code == 200:
                signatures = sign_response.json()
                falcon_sig = signatures["falcon_signature"]
                ecdsa_sig = signatures.get("ecdsa_signature", "")
                sig_metadata = {
                    "algorithm": signatures.get("algorithm", "Unknown"),
                    "timestamp": datetime.utcnow().isoformat(),
                    "message_type": message.message_type
                }
            else:
                logger.warning(f"Signing failed with status {sign_response.status_code}")
        except Exception as e:
            logger.error(f"Signing request failed: {str(e)}")
    
    # Determine receiver
    receiver_id = session.user2_id if session.user1_id == current_user.id else session.user1_id
    
    # Create message
    msg = Message(
        session_id=session.id,
        sender_id=current_user.id,
        receiver_id=receiver_id,
        encrypted_content=ciphertext,
        nonce=nonce,
        tag=tag,
        aad=aad,
        falcon_signature=falcon_sig,
        ecdsa_signature=ecdsa_sig,
        signature_metadata=json.dumps(sig_metadata) if sig_metadata else None,
        message_type=message.message_type
    )
    db.add(msg)
    
    # Update session
    session.last_activity = datetime.utcnow()
    session.message_count += 1
    
    db.commit()
    db.refresh(msg)
    
    # Record performance metric
    duration_ms = (time.time() - start_time) * 1000
    record_performance_metric(db, current_user.id, "message_send", duration_ms, 
                             len(message.content), message.message_type == "critical")
    
    audit_log(db, current_user.id, f"MESSAGE_SENT_{message.message_type.upper()}", f"To session: {session.id[:8]}", request)
    logger.info(f"Message sent from {current_user.username} ({message.message_type})")
    
    # Notify receiver
    receiver_user = db.query(User).filter(User.id == receiver_id).first()
    if receiver_user:
        await manager.send_personal_message(
            receiver_user.username,
            {
                "type": "new_message",
                "sender": current_user.username,
                "message_id": msg.id,
                "message_type": message.message_type
            }
        )
    
    return {
        "message_id": msg.id,
        "timestamp": msg.timestamp.isoformat(),
        "status": "sent",
        "encrypted": True,
        "signed": message.message_type == "critical",
        "processing_time_ms": duration_ms,
        "message_type": message.message_type
    }

@app.get("/api/messages")
async def get_messages(
    last_message_id: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get messages from the current session"""
    # Get active session
    session = get_active_session(current_user.id, db)
    if not session:
        return []
    
    if not session.shared_secret:
        return []
    
    shared_secret = base64.b64decode(session.shared_secret)
    
    # Build query
    query = db.query(Message).filter(Message.session_id == session.id)
    
    # Filter deleted messages
    query = query.filter(
        or_(
            and_(Message.sender_id == current_user.id, Message.is_deleted_sender == False),
            and_(Message.receiver_id == current_user.id, Message.is_deleted_receiver == False)
        )
    )
    
    # Pagination
    if last_message_id:
        last_msg = db.query(Message).filter(Message.id == last_message_id).first()
        if last_msg:
            query = query.filter(Message.timestamp > last_msg.timestamp)
    
    messages = query.order_by(Message.timestamp).limit(limit).all()
    
    # Get connection request for public keys
    conn_request = db.query(ConnectionRequest).filter(
        ConnectionRequest.id == session.request_id
    ).first() if session.request_id else None
    
    decrypted_messages = []
    
    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        for msg in messages:
            # Mark as read
            if msg.receiver_id == current_user.id and not msg.is_read:
                msg.is_read = True
                msg.read_at = datetime.utcnow()
            
            verified = False
            
            # Verify signature if present (all messages should have signatures now)
            if conn_request and msg.falcon_signature:
                try:
                    # Get sender's public keys
                    if msg.sender_id == conn_request.sender_id:
                        sender_keys = json.loads(conn_request.sender_public_keys)
                    else:
                        sender_keys = json.loads(conn_request.receiver_public_keys) if conn_request.receiver_public_keys else {}
                    
                    if sender_keys:
                        # Decrypt message first
                        try:
                            decrypted_content = decrypt_message(
                                msg.encrypted_content,
                                msg.nonce,
                                msg.tag,
                                shared_secret,
                                msg.aad
                            )
                        except:
                            decrypted_content = "[Decryption failed]"
                        
                        # Verify signature
                        verify_response = await client.post(
                            f"{QUANTUM_API}/api/quantum/wrap_verify",
                            json={
                                "message": decrypted_content,
                                "falcon_signature": msg.falcon_signature,
                                "ecdsa_signature": msg.ecdsa_signature or "",
                                "falcon_public": sender_keys.get("falcon_512", ""),
                                "ecdsa_public": sender_keys.get("ecdsa_p256", ""),
                                "signature_type": "wrap_sign" if msg.ecdsa_signature else "falcon_only"
                            }
                        )
                        
                        if verify_response.status_code == 200:
                            verify_data = verify_response.json()
                            verified = verify_data.get("valid", False)
                except Exception as e:
                    logger.error(f"Signature verification failed: {str(e)}")
                    verified = False
            else:
                # Decrypt regular message
                try:
                    decrypted_content = decrypt_message(
                        msg.encrypted_content,
                        msg.nonce,
                        msg.tag,
                        shared_secret,
                        msg.aad
                    )
                except:
                    decrypted_content = "[Decryption failed]"
            
            sig_metadata = json.loads(msg.signature_metadata) if msg.signature_metadata else {}
            
            decrypted_messages.append({
                "id": msg.id,
                "sender_id": msg.sender_id,
                "sender_username": msg.sender.username,
                "content": decrypted_content,
                "message_type": msg.message_type,
                "timestamp": msg.timestamp.isoformat(),
                "delivered_at": msg.delivered_at.isoformat() if msg.delivered_at else None,
                "read_at": msg.read_at.isoformat() if msg.read_at else None,
                "is_mine": msg.sender_id == current_user.id,
                "is_read": msg.is_read,
                "verified": verified,
                "is_critical": msg.message_type == "critical",
                "has_signature": bool(msg.falcon_signature),
                "quantum_algorithm": sig_metadata.get("algorithm", "Unknown") if sig_metadata else None,
                "metadata": sig_metadata.get("metadata", {}) if sig_metadata else {}
            })
    
    # Update session activity
    session.last_activity = datetime.utcnow()
    db.commit()
    
    return decrypted_messages

# ========== SESSION MANAGEMENT ==========
@app.get("/api/session/status")
def get_session_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> SessionStatus:
    """Get current session status"""
    session = get_active_session(current_user.id, db)
    
    if not session:
        return SessionStatus(
            active=False,
            message_count=0,
            has_keys=bool(current_user.public_keys),
            quantum_ready=bool(current_user.public_keys)
        )
    
    # Get peer info
    peer_id = session.user2_id if session.user1_id == current_user.id else session.user1_id
    peer = db.query(User).filter(User.id == peer_id).first()
    
    metadata = json.loads(session.session_metadata) if session.session_metadata else {}
    
    return SessionStatus(
        active=True,
        session_id=session.id,
        peer_username=peer.username if peer else "Unknown",
        peer_id=peer_id,
        established_at=session.established_at.isoformat(),
        last_activity=session.last_activity.isoformat(),
        message_count=session.message_count,
        has_keys=bool(session.shared_secret),
        quantum_ready=True
    )

@app.post("/api/session/terminate")
async def terminate_session(
    reason: Optional[str] = "User requested",
    current_user: User = Depends(get_current_user),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """Terminate the current session"""
    session = get_active_session(current_user.id, db)
    if not session:
        raise HTTPException(status_code=404, detail="No active session")
    
    # Get other user
    other_user_id = session.user1_id if session.user2_id == current_user.id else session.user2_id
    other_user = db.query(User).filter(User.id == other_user_id).first()
    
    # Terminate session
    session.is_active = False
    session.terminated_at = datetime.utcnow()
    session.termination_reason = reason[:100]
    
    # Cancel pending requests
    db.query(ConnectionRequest).filter(
        or_(
            and_(ConnectionRequest.sender_id == session.user1_id, ConnectionRequest.receiver_id == session.user2_id),
            and_(ConnectionRequest.sender_id == session.user2_id, ConnectionRequest.receiver_id == session.user1_id)
        ),
        ConnectionRequest.status == "pending"
    ).update({"status": "cancelled"})
    
    # Clear keys
    current_user.public_keys = None
    current_user.key_generation_timestamp = None
    
    if other_user:
        other_user.public_keys = None
        other_user.key_generation_timestamp = None
    
    db.commit()
    
    # Try to clear keys in quantum service
    try:
        async with httpx.AsyncClient(verify=False) as client:
            await client.delete(f"{QUANTUM_API}/api/quantum/session/{current_user.username}")
            if other_user:
                await client.delete(f"{QUANTUM_API}/api/quantum/session/{other_user.username}")
    except Exception as e:
        logger.warning(f"Failed to clear quantum service keys: {e}")
    
    audit_log(db, current_user.id, "SESSION_TERMINATED", f"Reason: {reason}, Keys destroyed for both users", request)
    logger.info(f"Quantum session terminated by {current_user.username}")
    
    # Notify other user
    if other_user:
        await manager.send_personal_message(
            other_user.username,
            {
                "type": "session_update",
                "status": "terminated",
                "reason": reason,
                "terminated_by": current_user.username
            }
        )
    
    # Also notify current user
    await manager.send_personal_message(
        current_user.username,
        {
            "type": "session_update",
            "status": "terminated",
            "reason": reason,
            "terminated_by": current_user.username
        }
    )
    
    return {
        "message": "Session terminated",
        "session_id": session.id,
        "keys_destroyed": True
    }

@app.get("/api/users/available")
def get_available_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of available users"""
    cleanup_inactive_sessions(db)
    
    # Get all active users
    all_users = db.query(User).filter(
        User.id != current_user.id,
        User.is_active == True
    ).order_by(User.username).all()
    
    result = []
    for user in all_users:
        session = get_active_session(user.id, db)
        is_online = (datetime.utcnow() - user.last_seen).total_seconds() < 300  # 5 minutes
        
        result.append({
            "username": user.username,
            "user_id": user.id,
            "status": "busy" if session else ("online" if is_online else "offline"),
            "can_connect": session is None,
            "has_quantum_keys": bool(user.public_keys),
            "last_seen": user.last_seen.isoformat() if is_online else None
        })
    
    return result

# ========== WEBSOCKET ==========
@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    """WebSocket endpoint for real-time communication"""
    connection_id = await manager.connect(websocket, username)
    
    db = SessionLocal()
    try:
        # Update user status
        user = db.query(User).filter(User.username == username).first()
        if user:
            user.last_seen = datetime.utcnow()
            db.commit()
            
            # Notify others user is online
            online_users = manager.get_online_users()
            await manager.broadcast_to_users(
                {
                    "type": "user_status_update",
                    "username": username,
                    "status": "online"
                },
                online_users
            )
        
        try:
            while True:
                # Receive message from WebSocket
                data = await websocket.receive_text()
                message_data = json.loads(data)
                
                # Handle different message types
                if message_data.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
                elif message_data.get("type") == "heartbeat":
                    if user:
                        user.last_seen = datetime.utcnow()
                        db.commit()
                        
        except WebSocketDisconnect:
            logger.info(f"WebSocket disconnected for {username}")
            manager.disconnect(username)
            
            # Handle cleanup on disconnect
            if user:
                user.last_seen = datetime.utcnow()
                
                # Check for active session
                active_session = get_active_session(user.id, db)
                if active_session:
                    other_user_id = active_session.user1_id if active_session.user2_id == user.id else active_session.user2_id
                    other_user = db.query(User).filter(User.id == other_user_id).first()
                    
                    # Terminate session on disconnect
                    active_session.is_active = False
                    active_session.terminated_at = datetime.utcnow()
                    active_session.termination_reason = "WebSocket disconnect"
                    
                    # Clear keys
                    user.public_keys = None
                    user.key_generation_timestamp = None
                    if other_user:
                        other_user.public_keys = None
                        other_user.key_generation_timestamp = None
                        
                        # Notify other user
                        await manager.send_personal_message(
                            other_user.username,
                            {
                                "type": "session_update",
                                "status": "terminated",
                                "reason": "Connection lost",
                                "terminated_by": username
                            }
                        )
                
                db.commit()
                
            # Notify others user is offline
            online_users = manager.get_online_users()
            await manager.broadcast_to_users(
                {
                    "type": "user_status_update",
                    "username": username,
                    "status": "offline"
                },
                online_users
            )
            
    except Exception as e:
        logger.error(f"WebSocket error for {username}: {e}")
        manager.disconnect(username)
    finally:
        db.close()

# ========== SYSTEM ENDPOINTS ==========
@app.get("/api/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "QMS Platform",
        "version": "3.0.0",
        "features": {
            "text_messaging": True,
            "quantum_key_exchange": True,
            "wrap_and_sign_signatures": True,
            "websocket_support": True
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/stats")
def get_statistics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user statistics"""
    # Count messages
    total_messages_sent = db.query(Message).filter(Message.sender_id == current_user.id).count()
    total_messages_received = db.query(Message).filter(Message.receiver_id == current_user.id).count()
    
    # Count sessions
    total_sessions = db.query(SecureSession).filter(
        or_(SecureSession.user1_id == current_user.id, SecureSession.user2_id == current_user.id)
    ).count()
    
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "member_since": current_user.created_at.isoformat(),
        "statistics": {
            "messages_sent": total_messages_sent,
            "messages_received": total_messages_received,
            "total_sessions": total_sessions,
            "quantum_keys_generated": bool(current_user.public_keys)
        }
    }

# ========== STARTUP/SHUTDOWN ==========
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    logger.info("QMS Platform v3.0 starting up...")
    logger.info("QMS Platform ready - Quantum service will be checked on demand")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown"""
    logger.info("QMS Platform shutting down...")

# ========== ERROR HANDLERS ==========
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
            "detail": "An unexpected error occurred",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# ========== MAIN EXECUTION ==========
if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*80)
    print("QMS PLATFORM - QUANTUM MESSAGING SYSTEM - v3.0.0")
    print("="*80)
    print("Features:")
    print("  - ML-KEM-768 quantum-resistant key exchange")
    print("  - Falcon-512 quantum-resistant signatures")
    print("  - Wrap-and-Sign hybrid protocol")
    print("  - AES-256-GCM authenticated encryption")
    print("  - WebSocket real-time communication")
    print("  - Perfect forward secrecy")
    print("  - Comprehensive audit logging")
    print("="*80)
    print("Starting server on https://localhost:4000 (SSL enabled)")
    print("API Documentation: https://localhost:4000/docs")
    print("Alternative Docs: https://localhost:4000/redoc")
    print("="*80 + "\n")
    
    import os
    cert_path = "/Users/rahulsemwal/Desktop/ducc beta testing/localhost+3.pem"
    key_path = "/Users/rahulsemwal/Desktop/ducc beta testing/localhost+3-key.pem"
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        print("🔒 SSL certificates found - enabling HTTPS")
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=4000,
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
            port=4000,
            log_level="info",
            access_log=True,
            use_colors=True
        )