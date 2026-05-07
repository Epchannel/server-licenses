"""
Authentication & Authorization module
"""

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
import bcrypt as bcrypt_lib
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
import os

from database import get_db, AdminUser

import secrets as _secrets

# JWT Settings
SECRET_KEY = os.getenv("JWT_SECRET_KEY", _secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

security = HTTPBearer()


# ==================== Password Functions ====================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password"""
    return bcrypt_lib.checkpw(plain_password.encode(), hashed_password.encode())


def get_password_hash(password: str) -> str:
    """Hash password"""
    return bcrypt_lib.hashpw(password.encode(), bcrypt_lib.gensalt()).decode()


# ==================== JWT Functions ====================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """Decode JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# ==================== Authentication Functions ====================

def authenticate_user(db: Session, username: str, password: str) -> Optional[AdminUser]:
    """Authenticate admin user"""
    user = db.query(AdminUser).filter(AdminUser.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    if not user.active:
        return None
    return user


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> AdminUser:
    """Get current authenticated user from JWT token"""
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token = credentials.credentials
    payload = decode_access_token(token)
    
    if payload is None:
        raise credentials_exception
    
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception
    
    user = db.query(AdminUser).filter(AdminUser.username == username).first()
    if user is None:
        raise credentials_exception
    
    if not user.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    
    return user


def get_current_superuser(
    current_user: AdminUser = Depends(get_current_user)
) -> AdminUser:
    """Get current user and verify superuser"""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user


# ==================== API Key Authentication (Optional) ====================

API_KEYS = {}
if os.getenv("API_KEY_1"):
    API_KEYS[os.getenv("API_KEY_1")] = "client-1"


def verify_api_key(request: Request) -> str:
    """Verify API key from header"""
    api_key = request.headers.get("X-API-Key")
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key required"
        )
    
    client_name = API_KEYS.get(api_key)
    if not client_name:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key"
        )
    
    return client_name


# ==================== Rate Limiting ====================

from collections import defaultdict
from time import time

# Simple in-memory rate limiter
# For production, use Redis
rate_limit_storage = defaultdict(list)

def rate_limit_check(
    key: str,
    max_requests: int = 100,
    window_seconds: int = 60
) -> bool:
    """
    Check rate limit
    Returns True if allowed, False if rate limited
    """
    now = time()
    
    # Remove old requests outside window
    rate_limit_storage[key] = [
        req_time for req_time in rate_limit_storage[key]
        if now - req_time < window_seconds
    ]
    
    # Check if over limit
    if len(rate_limit_storage[key]) >= max_requests:
        return False
    
    # Add current request
    rate_limit_storage[key].append(now)
    return True


def rate_limit_middleware(request: Request, key_prefix: str = "ip"):
    """Rate limit middleware"""
    
    # Get client identifier (IP or API key)
    if key_prefix == "ip":
        client_id = request.client.host
    else:
        client_id = request.headers.get("X-API-Key", request.client.host)
    
    key = f"{key_prefix}:{client_id}"
    
    if not rate_limit_check(key, max_requests=100, window_seconds=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )

