"""
License Server V2 - Enhanced Version
Features:
- Database integration (SQLite/PostgreSQL)
- Admin panel with authentication
- Monitoring & Analytics
- Rate limiting
- Audit logging
- Security improvements
"""

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy.orm import Session
import hmac
import hashlib
import secrets
import os

# Import our modules
from database import (
    get_db, init_db, License, LicenseLog, AdminUser, SystemStat,
    get_license_by_key, create_license, update_license, delete_license,
    log_license_activity, get_stats, create_default_admin,
    ToolUser, ToolLicense, AVAILABLE_TOOLS,
    create_tool_user, get_tool_user, get_tool_user_by_email,
    get_all_tool_users, update_tool_user, delete_tool_user,
    create_tool_license, get_tool_license_by_key, get_tool_licenses_for_user,
    get_all_tool_licenses, update_tool_license, delete_tool_license,
    verify_tool_license, generate_tool_license_key
)
from auth import (
    authenticate_user, create_access_token, get_current_user, get_current_superuser,
    rate_limit_middleware, get_password_hash
)

# Initialize FastAPI app
app = FastAPI(
    title="License Server V2",
    description="Enhanced License Server with Admin Panel & Monitoring",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Secret key for signature
SECRET_KEY = os.getenv("SECRET_KEY", "Hiep-dep-trai-nhat-Viet-Nam-2026")

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    init_db()
    create_default_admin()
    print("✅ License Server V2 started!")


# ==================== Pydantic Models ====================

class VerifyRequest(BaseModel):
    license_key: str
    device_id: str
    device_name: Optional[str] = None


class VerifyResponse(BaseModel):
    valid: bool
    expire_at: Optional[str] = None
    features: Optional[List[str]] = None
    message: str
    signature: str


class HeartbeatRequest(BaseModel):
    license_key: str
    device_id: str


class HeartbeatResponse(BaseModel):
    valid: bool
    message: str
    timestamp: str
    signature: str


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    username: str


class LicenseCreate(BaseModel):
    license_key: Optional[str] = None  # Auto-generate if not provided
    expire_days: int = 365
    features: List[str] = ["basic"]
    max_devices: int = 1
    customer_email: Optional[str] = None
    customer_name: Optional[str] = None
    notes: Optional[str] = None


class LicenseUpdate(BaseModel):
    active: Optional[bool] = None
    expire_at: Optional[datetime] = None
    features: Optional[List[str]] = None
    max_devices: Optional[int] = None
    customer_email: Optional[str] = None
    customer_name: Optional[str] = None
    notes: Optional[str] = None


class LicenseResponse(BaseModel):
    id: int
    license_key: str
    device_id: Optional[str]
    device_name: Optional[str]
    active: bool
    expire_at: datetime
    created_at: datetime
    activated_at: Optional[datetime]
    last_verified_at: Optional[datetime]
    features: List[str]
    max_devices: int
    customer_email: Optional[str]
    customer_name: Optional[str]
    notes: Optional[str]
    verify_count: int
    heartbeat_count: int
    
    class Config:
        from_attributes = True


# ==================== Helper Functions ====================

def generate_signature(data: str) -> str:
    """Generate HMAC SHA256 signature"""
    return hmac.new(
        SECRET_KEY.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()


def generate_license_key(prefix: str = "LIC") -> str:
    """Generate random license key"""
    random_part = secrets.token_hex(16).upper()
    return f"{prefix}-{random_part[:8]}-{random_part[8:16]}-{random_part[16:24]}"


def get_client_ip(request: Request) -> str:
    """Get client IP address"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host


# ==================== Public API Endpoints ====================

@app.get("/")
def root():
    """Health check endpoint"""
    return {
        "service": "License Server V2",
        "version": "2.0.0",
        "status": "running",
        "features": [
            "License verification",
            "Admin panel",
            "Analytics",
            "Rate limiting",
            "Audit logging"
        ]
    }


@app.post("/license/verify", response_model=VerifyResponse)
async def verify_license(
    request: Request,
    verify_req: VerifyRequest,
    db: Session = Depends(get_db)
):
    """
    Verify license key and bind to device
    Rate limited: 100 requests per minute per IP
    """
    
    # Rate limiting
    try:
        rate_limit_middleware(request, key_prefix="verify")
    except HTTPException as e:
        # Log rate limit exceeded
        log_license_activity(
            db, verify_req.license_key, "verify", "rate_limited",
            "Rate limit exceeded", verify_req.device_id, get_client_ip(request)
        )
        raise e
    
    license_key = verify_req.license_key
    device_id = verify_req.device_id
    device_name = verify_req.device_name
    client_ip = get_client_ip(request)

    # Get license from old licenses table
    license_obj = get_license_by_key(db, license_key)

    if not license_obj:
        # Fallback: check tool_licenses table
        tool_result = verify_tool_license(
            db, tool_code=None, license_key=license_key,
            device_id=device_id, device_name=device_name,
            ip_address=client_ip
        )

        if tool_result.get("valid") is not None:
            # Found in tool_licenses — return result
            sig_data = f"{'valid' if tool_result['valid'] else 'invalid'}|{license_key}|{device_id}|{tool_result.get('expire_at', '')}"
            signature = generate_signature(sig_data)
            return VerifyResponse(
                valid=tool_result["valid"],
                expire_at=tool_result.get("expire_at"),
                features=tool_result.get("features"),
                message=tool_result["message"],
                signature=signature
            )

        # Not found anywhere
        log_license_activity(
            db, license_key, "verify", "failed",
            "Invalid license key", device_id, client_ip
        )
        signature = generate_signature(f"invalid|{license_key}|{device_id}")
        return VerifyResponse(
            valid=False,
            message="Invalid license key",
            signature=signature
        )

    # --- Old licenses table logic (unchanged) ---

    # Check if active
    if not license_obj.active:
        log_license_activity(
            db, license_key, "verify", "failed",
            "License deactivated", device_id, client_ip
        )
        signature = generate_signature(f"inactive|{license_key}|{device_id}")
        return VerifyResponse(
            valid=False,
            message="License has been deactivated",
            signature=signature
        )

    # Check expiration
    if datetime.utcnow() > license_obj.expire_at:
        log_license_activity(
            db, license_key, "verify", "failed",
            "License expired", device_id, client_ip
        )
        signature = generate_signature(f"expired|{license_key}|{device_id}")
        return VerifyResponse(
            valid=False,
            expire_at=license_obj.expire_at.isoformat(),
            message="License has expired",
            signature=signature
        )

    # Device binding logic
    if license_obj.device_id is None:
        license_obj.device_id = device_id
        license_obj.device_name = device_name
        license_obj.activated_at = datetime.utcnow()
        message = "License activated and bound to device"
        action = "activate"
    elif license_obj.device_id == device_id:
        if device_name and device_name != license_obj.device_name:
            license_obj.device_name = device_name
        message = "License verified successfully"
        action = "verify"
    else:
        log_license_activity(
            db, license_key, "verify", "failed",
            "Device mismatch", device_id, client_ip
        )
        signature = generate_signature(f"device_mismatch|{license_key}|{device_id}")
        return VerifyResponse(
            valid=False,
            message="License is bound to another device",
            signature=signature
        )

    license_obj.last_verified_at = datetime.utcnow()
    license_obj.verify_count += 1
    db.commit()

    log_license_activity(
        db, license_key, action, "success",
        message, device_id, client_ip
    )

    data_to_sign = f"valid|{license_key}|{device_id}|{license_obj.expire_at.isoformat()}"
    signature = generate_signature(data_to_sign)

    return VerifyResponse(
        valid=True,
        expire_at=license_obj.expire_at.isoformat(),
        features=license_obj.features,
        message=message,
        signature=signature
    )



# ==================== Admin Authentication ====================

@app.post("/admin/login", response_model=LoginResponse)
async def admin_login(
    login_req: LoginRequest,
    db: Session = Depends(get_db)
):
    """Admin login endpoint"""
    
    user = authenticate_user(db, login_req.username, login_req.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    # Create access token
    access_token = create_access_token(data={"sub": user.username})
    
    # Update last login
    user.last_login_at = datetime.utcnow()
    db.commit()
    
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        username=user.username
    )


# ==================== Admin API Endpoints ====================

@app.get("/admin/licenses", response_model=List[LicenseResponse])
async def list_licenses(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = False,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    """List all licenses (requires authentication)"""
    
    query = db.query(License)
    
    if active_only:
        query = query.filter(License.active == True)
    
    licenses = query.offset(skip).limit(limit).all()
    return licenses


@app.get("/admin/licenses/{license_key}", response_model=LicenseResponse)
async def get_license(
    license_key: str,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    """Get specific license details"""
    
    license_obj = get_license_by_key(db, license_key)
    if not license_obj:
        raise HTTPException(status_code=404, detail="License not found")
    
    return license_obj


@app.post("/admin/licenses", response_model=LicenseResponse, status_code=201)
async def create_new_license(
    license_data: LicenseCreate,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    """Create new license"""
    
    # Generate license key if not provided
    license_key = license_data.license_key or generate_license_key()
    
    # Check if license key already exists
    existing = get_license_by_key(db, license_key)
    if existing:
        raise HTTPException(status_code=400, detail="License key already exists")
    
    # Calculate expiration date
    expire_at = datetime.utcnow() + timedelta(days=license_data.expire_days)
    
    # Create license
    new_license = create_license(db, {
        "license_key": license_key,
        "expire_at": expire_at,
        "features": license_data.features,
        "max_devices": license_data.max_devices,
        "customer_email": license_data.customer_email,
        "customer_name": license_data.customer_name,
        "notes": license_data.notes
    })
    
    return new_license


@app.patch("/admin/licenses/{license_key}", response_model=LicenseResponse)
async def update_license_endpoint(
    license_key: str,
    license_data: LicenseUpdate,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    """Update license"""
    
    # Get license
    license_obj = get_license_by_key(db, license_key)
    if not license_obj:
        raise HTTPException(status_code=404, detail="License not found")
    
    # Update fields
    update_data = license_data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(license_obj, key, value)
    
    db.commit()
    db.refresh(license_obj)
    
    return license_obj


@app.delete("/admin/licenses/{license_key}")
async def delete_license_endpoint(
    license_key: str,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_superuser)
):
    """Delete license (superuser only)"""
    
    if delete_license(db, license_key):
        return {"message": "License deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="License not found")


@app.get("/admin/logs")
async def get_logs(
    license_key: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    """Get activity logs"""
    
    query = db.query(LicenseLog).order_by(LicenseLog.created_at.desc())
    
    if license_key:
        query = query.filter(LicenseLog.license_key == license_key)
    
    logs = query.limit(limit).all()
    
    return [
        {
            "id": log.id,
            "license_key": log.license_key,
            "device_id": log.device_id,
            "action": log.action,
            "status": log.status,
            "message": log.message,
            "ip_address": log.ip_address,
            "created_at": log.created_at.isoformat()
        }
        for log in logs
    ]


@app.get("/admin/stats")
async def get_statistics(
    days: int = 30,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    """Get system statistics"""
    
    stats = get_stats(db, days)
    
    # Additional stats
    from sqlalchemy import func
    
    # Top licenses by usage
    top_licenses = db.query(
        License.license_key,
        License.customer_name,
        License.verify_count,
        License.heartbeat_count
    ).order_by(
        (License.verify_count + License.heartbeat_count).desc()
    ).limit(10).all()
    
    stats["top_licenses"] = [
        {
            "license_key": lic[0],
            "customer_name": lic[1],
            "total_requests": lic[2] + lic[3]
        }
        for lic in top_licenses
    ]
    
    return stats


# ==================== Admin Panel UI ====================

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    """Serve admin panel HTML"""
    return HTMLResponse(content=open("static/admin.html").read())


# ==================== Tool Management Panel ====================

@app.get("/phamhonghiep", response_class=HTMLResponse)
async def tool_admin_panel():
    """Serve tool management admin panel"""
    return HTMLResponse(content=open("static/panel.html").read())


# ==================== Tool User Management API ====================

class ToolUserCreate(BaseModel):
    email: str
    name: str
    telegram_id: Optional[str] = None

class ToolUserUpdate(BaseModel):
    email: Optional[str] = None
    name: Optional[str] = None
    telegram_id: Optional[str] = None
    active: Optional[bool] = None


@app.get("/panel/api/users")
async def panel_list_users(
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    users = get_all_tool_users(db)
    result = []
    for u in users:
        licenses = get_tool_licenses_for_user(db, u.id)
        result.append({
            "id": u.id,
            "email": u.email,
            "name": u.name,
            "telegram_id": u.telegram_id,
            "active": u.active,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "licenses_count": len(licenses),
            "licenses": [
                {
                    "id": lic.id,
                    "tool_code": lic.tool_code,
                    "tool_name": AVAILABLE_TOOLS.get(lic.tool_code, {}).get("name", lic.tool_code),
                    "license_key": lic.license_key,
                    "active": lic.active,
                    "expire_at": lic.expire_at.isoformat() if lic.expire_at else None,
                    "use_count": lic.use_count,
                    "device_id": lic.device_id,
                    "last_used_at": lic.last_used_at.isoformat() if lic.last_used_at else None
                }
                for lic in licenses
            ]
        })
    return result


@app.post("/panel/api/users", status_code=201)
async def panel_create_user(
    user_data: ToolUserCreate,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    existing = get_tool_user_by_email(db, user_data.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    user = create_tool_user(db, user_data.dict())
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "telegram_id": user.telegram_id,
        "active": user.active,
        "created_at": user.created_at.isoformat() if user.created_at else None
    }


@app.patch("/panel/api/users/{user_id}")
async def panel_update_user(
    user_id: int,
    user_data: ToolUserUpdate,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    update_data = user_data.dict(exclude_unset=True)
    user = update_tool_user(db, user_id, update_data)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "telegram_id": user.telegram_id,
        "active": user.active
    }


@app.delete("/panel/api/users/{user_id}")
async def panel_delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    if delete_tool_user(db, user_id):
        return {"message": "User deleted successfully"}
    raise HTTPException(status_code=404, detail="User not found")


# ==================== Tool License Management API ====================

class ToolLicenseCreate(BaseModel):
    user_id: int
    tool_code: str
    expire_days: int = 365
    notes: Optional[str] = None

class ToolLicenseUpdate(BaseModel):
    active: Optional[bool] = None
    expire_at: Optional[str] = None
    notes: Optional[str] = None
    device_id: Optional[str] = None


@app.get("/panel/api/licenses")
async def panel_list_licenses(
    tool_code: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    licenses = get_all_tool_licenses(db, tool_code)
    result = []
    for lic in licenses:
        user = get_tool_user(db, lic.user_id)
        result.append({
            "id": lic.id,
            "user_id": lic.user_id,
            "user_name": user.name if user else "Unknown",
            "user_email": user.email if user else "Unknown",
            "tool_code": lic.tool_code,
            "tool_name": AVAILABLE_TOOLS.get(lic.tool_code, {}).get("name", lic.tool_code),
            "license_key": lic.license_key,
            "active": lic.active,
            "expire_at": lic.expire_at.isoformat() if lic.expire_at else None,
            "created_at": lic.created_at.isoformat() if lic.created_at else None,
            "last_used_at": lic.last_used_at.isoformat() if lic.last_used_at else None,
            "use_count": lic.use_count,
            "device_id": lic.device_id,
            "notes": lic.notes
        })
    return result


@app.post("/panel/api/licenses", status_code=201)
async def panel_create_license(
    lic_data: ToolLicenseCreate,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    # Validate tool_code
    if lic_data.tool_code not in AVAILABLE_TOOLS:
        raise HTTPException(status_code=400, detail=f"Invalid tool code: {lic_data.tool_code}")

    # Validate user exists
    user = get_tool_user(db, lic_data.user_id)
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    expire_at = datetime.utcnow() + timedelta(days=lic_data.expire_days)
    lic = create_tool_license(db, {
        "user_id": lic_data.user_id,
        "tool_code": lic_data.tool_code,
        "expire_at": expire_at,
        "notes": lic_data.notes
    })
    return {
        "id": lic.id,
        "license_key": lic.license_key,
        "tool_code": lic.tool_code,
        "tool_name": AVAILABLE_TOOLS.get(lic.tool_code, {}).get("name", lic.tool_code),
        "expire_at": lic.expire_at.isoformat(),
        "user_name": user.name
    }


@app.patch("/panel/api/licenses/{license_id}")
async def panel_update_license(
    license_id: int,
    lic_data: ToolLicenseUpdate,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    update_data = lic_data.dict(exclude_unset=True)
    if "expire_at" in update_data and update_data["expire_at"]:
        update_data["expire_at"] = datetime.fromisoformat(update_data["expire_at"])
    lic = update_tool_license(db, license_id, update_data)
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    return {"message": "License updated", "id": lic.id}


@app.delete("/panel/api/licenses/{license_id}")
async def panel_delete_license(
    license_id: int,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    if delete_tool_license(db, license_id):
        return {"message": "License deleted successfully"}
    raise HTTPException(status_code=404, detail="License not found")


@app.post("/panel/api/licenses/{license_id}/reset-device")
async def panel_reset_device(
    license_id: int,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    lic = update_tool_license(db, license_id, {"device_id": None})
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
    return {"message": "Device binding reset successfully"}


# ==================== Tool Info API ====================

@app.get("/panel/api/tools")
async def panel_list_tools(
    current_user: AdminUser = Depends(get_current_user)
):
    return list(AVAILABLE_TOOLS.values())


@app.get("/panel/api/stats")
async def panel_stats(
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user)
):
    total_users = db.query(ToolUser).count()
    active_users = db.query(ToolUser).filter(ToolUser.active == True).count()
    total_licenses = db.query(ToolLicense).count()
    active_licenses = db.query(ToolLicense).filter(
        ToolLicense.active == True,
        ToolLicense.expire_at > datetime.utcnow()
    ).count()
    expired_licenses = db.query(ToolLicense).filter(
        ToolLicense.expire_at <= datetime.utcnow()
    ).count()

    # Per-tool stats
    tool_stats = []
    for code, tool in AVAILABLE_TOOLS.items():
        count = db.query(ToolLicense).filter(ToolLicense.tool_code == code).count()
        active_count = db.query(ToolLicense).filter(
            ToolLicense.tool_code == code,
            ToolLicense.active == True,
            ToolLicense.expire_at > datetime.utcnow()
        ).count()
        tool_stats.append({
            "code": code,
            "name": tool["name"],
            "total": count,
            "active": active_count
        })

    return {
        "total_users": total_users,
        "active_users": active_users,
        "total_licenses": total_licenses,
        "active_licenses": active_licenses,
        "expired_licenses": expired_licenses,
        "tool_stats": tool_stats
    }


# ==================== Public Tool Verify Endpoints ====================

class ToolVerifyRequest(BaseModel):
    license_key: str
    device_id: Optional[str] = None
    device_name: Optional[str] = None


@app.post("/api/v2/{tool_code}/verify")
async def api_verify_tool(
    tool_code: str,
    req: ToolVerifyRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Public endpoint to verify a tool license.
    Each license key only works with the assigned tool.
    """
    if tool_code not in AVAILABLE_TOOLS:
        raise HTTPException(status_code=404, detail="Tool not found")

    client_ip = get_client_ip(request)

    result = verify_tool_license(
        db, tool_code, req.license_key,
        device_id=req.device_id,
        device_name=req.device_name,
        ip_address=client_ip
    )

    # Generate signature
    sig_data = f"{tool_code}|{req.license_key}|{result.get('valid')}|{result.get('expire_at', '')}"
    signature = generate_signature(sig_data)
    result["signature"] = signature

    return result


# ==================== Tool Heartbeat Endpoint ====================

class ToolHeartbeatRequest(BaseModel):
    license_key: str
    device_id: str


@app.post("/license/heartbeat")
async def tool_heartbeat(
    request: Request,
    hb_req: ToolHeartbeatRequest,
    db: Session = Depends(get_db)
):
    """
    Heartbeat endpoint for tool licenses.
    Used to check if license is still valid and track usage.
    Recommended: send every 5-10 minutes while tool is running.
    """
    license_key = hb_req.license_key
    device_id = hb_req.device_id
    client_ip = get_client_ip(request)
    timestamp = datetime.utcnow().isoformat()

    # Find the license (from tool_licenses table)
    from database import ToolLicense as TL
    lic = db.query(TL).filter(TL.license_key == license_key).first()

    if not lic:
        # Fallback: check old License table for backward compatibility
        old_lic = get_license_by_key(db, license_key)
        if old_lic:
            # Use existing heartbeat logic for old licenses
            if not old_lic.active:
                signature = generate_signature(f"inactive|heartbeat|{timestamp}")
                return {"valid": False, "message": "License deactivated", "timestamp": timestamp, "signature": signature}
            if datetime.utcnow() > old_lic.expire_at:
                signature = generate_signature(f"expired|heartbeat|{timestamp}")
                return {"valid": False, "message": "License expired", "timestamp": timestamp, "signature": signature}
            if old_lic.device_id != device_id:
                signature = generate_signature(f"device_mismatch|heartbeat|{timestamp}")
                return {"valid": False, "message": "Device mismatch", "timestamp": timestamp, "signature": signature}
            old_lic.heartbeat_count += 1
            old_lic.last_verified_at = datetime.utcnow()
            db.commit()
            signature = generate_signature(f"valid|heartbeat|{timestamp}")
            return {"valid": True, "message": "Heartbeat OK", "timestamp": timestamp, "signature": signature}

        signature = generate_signature(f"invalid|heartbeat|{timestamp}")
        return {"valid": False, "message": "Invalid license key", "timestamp": timestamp, "signature": signature}

    # Tool license heartbeat
    if not lic.active:
        signature = generate_signature(f"inactive|heartbeat|{timestamp}")
        return {"valid": False, "message": "License deactivated", "timestamp": timestamp, "signature": signature}

    if datetime.utcnow() > lic.expire_at:
        signature = generate_signature(f"expired|heartbeat|{timestamp}")
        return {"valid": False, "message": "License expired", "timestamp": timestamp, "signature": signature}

    if lic.device_id and lic.device_id != device_id:
        signature = generate_signature(f"device_mismatch|heartbeat|{timestamp}")
        return {"valid": False, "message": "Device mismatch", "timestamp": timestamp, "signature": signature}

    # Update usage tracking
    lic.last_used_at = datetime.utcnow()
    lic.use_count += 1
    lic.ip_address = client_ip
    db.commit()

    signature = generate_signature(f"valid|heartbeat|{timestamp}")
    return {
        "valid": True,
        "message": "Heartbeat OK",
        "timestamp": timestamp,
        "signature": signature
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
