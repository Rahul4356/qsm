# Quantum Messaging System - Backend

Post-quantum secure messaging backend built with FastAPI and quantum cryptography.

## Features

- **Post-Quantum Cryptography**: ML-KEM-768 key exchange and Falcon-512 digital signatures
- **FastAPI Backend**: High-performance API with automatic OpenAPI documentation
- **SQLite Database**: Message storage with quantum encryption metadata
- **User Authentication**: JWT-based authentication with secure session management
- **Real-time Messaging**: WebSocket support for instant message delivery
- **Connection Management**: Quantum-safe connection establishment between users

## Tech Stack

- **FastAPI** - Modern Python web framework
- **SQLAlchemy** - Database ORM
- **SQLite** - Lightweight database
- **liboqs-python** - Post-quantum cryptography library
- **Cryptography** - Additional cryptographic primitives
- **PyJWT** - JSON Web Token implementation

## Installation

### Prerequisites

1. **Python 3.8+**
2. **Virtual Environment** (recommended)

### Setup

1. **Create and activate virtual environment**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   # Main API server (port 4000)
   python app.py
   
   # Quantum service (port 3001) - in separate terminal
   python service.py
   ```

## API Endpoints

### Authentication
- `POST /api/register` - User registration
- `POST /api/login` - User login
- `POST /api/logout` - User logout

### User Management
- `GET /api/users/available` - List available users
- `GET /api/users/me` - Current user information

### Connection Management
- `POST /api/connection/request` - Send connection request
- `POST /api/connection/respond` - Accept/reject connection request
- `GET /api/connection/pending` - Get pending requests

### Session Management
- `GET /api/session/status` - Current session status
- `POST /api/session/terminate` - End current session

### Messaging
- `POST /api/message/send` - Send encrypted message
- `GET /api/messages` - Get message history

### Quantum Service (Port 3001)
- `POST /api/quantum/keygen` - Generate ML-KEM-768 keypairs
- `POST /api/quantum/sign` - Create Falcon-512 signatures
- `POST /api/quantum/verify` - Verify signatures

## Security Features

### Post-Quantum Cryptography
- **ML-KEM-768**: NIST-standardized key encapsulation mechanism
- **Falcon-512**: Digital signature algorithm resistant to quantum attacks
- **AES-256-GCM**: Symmetric encryption with authentication

### Message Security
- **End-to-End Encryption**: Messages encrypted before database storage
- **Digital Signatures**: Critical messages signed with Falcon-512
- **Additional Authenticated Data (AAD)**: Session metadata protection
- **Forward Secrecy**: Quantum keys rotated per session

### Authentication & Authorization
- **JWT Tokens**: Secure session management
- **Password Hashing**: bcrypt with salt
- **Session Isolation**: Each conversation uses unique quantum keys

## Database Schema

### Users Table
- `id`: Primary key
- `username`: Unique username
- `email`: User email
- `password_hash`: bcrypt hashed password
- `created_at`: Account creation timestamp

### Messages Table
- `id`: Primary key
- `session_id`: Foreign key to sessions
- `sender_id`: Foreign key to users
- `content`: Encrypted message content
- `message_type`: 'secured' or 'critical'
- `signature_falcon`: Falcon-512 signature (for critical messages)
- `signature_ecdsa`: ECDSA signature (backup)
- `timestamp`: Message creation time
- `verified`: Signature verification status

### Sessions Table
- `id`: Primary key
- `user1_id`, `user2_id`: Participating users
- `session_key`: Encrypted AES key
- `ml_kem_keys`: Quantum key exchange data
- `created_at`: Session start time
- `is_active`: Session status

## Configuration

### Environment Variables
- `SECRET_KEY`: JWT signing secret
- `DATABASE_URL`: Database connection string
- `QUANTUM_SERVICE_URL`: Quantum service endpoint

### Default Ports
- **Main API**: 4000
- **Quantum Service**: 3001

## Development

### Running Tests
```bash
python -m pytest tests/
```

### API Documentation
Visit `http://localhost:4000/docs` for interactive API documentation.

### Database Management
```bash
# Reset database
rm qms_quantum.db

# View database
sqlite3 qms_quantum.db
```

## Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up --build

# Run specific service
docker-compose up backend
```

## Security Considerations

- Use HTTPS in production
- Regularly rotate JWT secrets
- Monitor for quantum key exhaustion
- Implement rate limiting
- Use secure random number generation
- Regular security audits of quantum implementations

## Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure ports 4000 and 3001 are available
2. **liboqs installation**: May require system dependencies
3. **Database permissions**: Ensure write access to database file
4. **Memory usage**: Quantum operations can be memory-intensive

### Logs
- Application logs: Console output
- Platform logs: `qms_platform.log`
- Quantum service logs: `quantum_service.log`