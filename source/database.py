"""
Database module for License Server
Support SQLite (default) and PostgreSQL
"""

from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, Text, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime
from typing import Optional, List, Dict, Any
import os
import secrets

# Database URL - Can switch to PostgreSQL in production
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./license_server.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# ==================== Models ====================

class License(Base):
    """License model"""
    __tablename__ = "licenses"
    
    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String(100), unique=True, index=True, nullable=False)
    device_id = Column(String(100), nullable=True)
    device_name = Column(String(200), nullable=True)  # Optional friendly name
    
    # License info
    active = Column(Boolean, default=True)
    expire_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    activated_at = Column(DateTime, nullable=True)  # First activation time
    last_verified_at = Column(DateTime, nullable=True)
    
    # Features (stored as JSON)
    features = Column(JSON, default=list)
    max_devices = Column(Integer, default=1)
    
    # Customer info
    customer_email = Column(String(200), nullable=True)
    customer_name = Column(String(200), nullable=True)
    notes = Column(Text, nullable=True)
    
    # Usage tracking
    verify_count = Column(Integer, default=0)
    heartbeat_count = Column(Integer, default=0)


class LicenseLog(Base):
    """License activity log"""
    __tablename__ = "license_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String(100), index=True)
    device_id = Column(String(100), nullable=True)
    
    action = Column(String(50))  # verify, heartbeat, activate, deactivate, etc.
    status = Column(String(20))  # success, failed
    message = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)


class AdminUser(Base):
    """Admin user model"""
    __tablename__ = "admin_users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(200), nullable=True)
    password_hash = Column(String(200), nullable=False)
    
    active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)


class SystemStat(Base):
    """System statistics (daily aggregated)"""
    __tablename__ = "system_stats"
    
    id = Column(Integer, primary_key=True, index=True)
    date = Column(DateTime, index=True)
    
    # Counts
    total_licenses = Column(Integer, default=0)
    active_licenses = Column(Integer, default=0)
    expired_licenses = Column(Integer, default=0)
    
    verify_requests = Column(Integer, default=0)
    verify_success = Column(Integer, default=0)
    verify_failed = Column(Integer, default=0)
    
    heartbeat_requests = Column(Integer, default=0)
    heartbeat_success = Column(Integer, default=0)
    heartbeat_failed = Column(Integer, default=0)


class Tool(Base):
    """Tool definition model - stored in database for dynamic management"""
    __tablename__ = "tools"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(200), nullable=False)
    prefix = Column(String(50), default="EPMMO")
    key_prefix = Column(String(50), default="")
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# ==================== Tool Definitions ====================
# This dict is loaded from the database at startup
AVAILABLE_TOOLS = {}

# Default tools to seed on first run
_DEFAULT_TOOLS = [
    {"code": "VER_PHONE_VEO", "name": "Ver Phone Veo 3", "prefix": "EPMMO", "key_prefix": "VER"},
    {"code": "CHECK_VEO3", "name": "Check Ultra Veo 3", "prefix": "EPMMO", "key_prefix": "CHECK"},
    {"code": "PICK_VEO3", "name": "Pick User Veo 3", "prefix": "EPMMO", "key_prefix": "PICK"},
    {"code": "CHANGE_PASS", "name": "Change Pass Veo 3", "prefix": "EPMMO", "key_prefix": "PASS"},
]


def load_tools_from_db():
    """Load all active tools from database into AVAILABLE_TOOLS dict"""
    global AVAILABLE_TOOLS
    db = SessionLocal()
    try:
        tools = db.query(Tool).filter(Tool.active == True).all()
        AVAILABLE_TOOLS.clear()
        for t in tools:
            AVAILABLE_TOOLS[t.code] = {
                "id": t.id,
                "name": t.name,
                "code": t.code,
                "prefix": t.prefix,
                "key_prefix": t.key_prefix,
                "endpoint": f"/api/v2/{t.code}/verify"
            }
        print(f"✅ Loaded {len(AVAILABLE_TOOLS)} tools from database")
    finally:
        db.close()


def seed_default_tools():
    """Seed default tools into database if none exist"""
    db = SessionLocal()
    try:
        count = db.query(Tool).count()
        if count == 0:
            for t in _DEFAULT_TOOLS:
                tool = Tool(**t)
                db.add(tool)
            db.commit()
            print(f"✅ Seeded {len(_DEFAULT_TOOLS)} default tools")
        else:
            print(f"✅ {count} tools already in database")
    finally:
        db.close()


def create_tool_in_db(db: Session, data: Dict[str, Any]) -> Tool:
    """Create a new tool"""
    tool = Tool(**data)
    db.add(tool)
    db.commit()
    db.refresh(tool)
    # Reload AVAILABLE_TOOLS
    load_tools_from_db()
    return tool


def get_all_tools_from_db(db: Session) -> List[Tool]:
    """Get all tools"""
    return db.query(Tool).all()


def update_tool_in_db(db: Session, tool_id: int, data: Dict[str, Any]) -> Optional[Tool]:
    """Update a tool"""
    tool = db.query(Tool).filter(Tool.id == tool_id).first()
    if tool:
        for key, value in data.items():
            setattr(tool, key, value)
        db.commit()
        db.refresh(tool)
        load_tools_from_db()
    return tool


def delete_tool_from_db(db: Session, tool_id: int) -> bool:
    """Delete a tool"""
    tool = db.query(Tool).filter(Tool.id == tool_id).first()
    if tool:
        db.delete(tool)
        db.commit()
        load_tools_from_db()
        return True
    return False


class ToolUser(Base):
    """Tool user model"""
    __tablename__ = "tool_users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(200), unique=True, index=True, nullable=False)
    name = Column(String(200), nullable=False)
    telegram_id = Column(String(100), nullable=True)

    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    tool_licenses = relationship("ToolLicense", back_populates="user", cascade="all, delete-orphan")


class ToolLicense(Base):
    """Tool license model - links a user to a tool with a license key"""
    __tablename__ = "tool_licenses"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("tool_users.id"), nullable=False)
    tool_code = Column(String(50), nullable=False, index=True)
    license_key = Column(String(100), unique=True, index=True, nullable=False)

    active = Column(Boolean, default=True)
    expire_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    use_count = Column(Integer, default=0)
    device_id = Column(String(200), nullable=True)
    device_name = Column(String(200), nullable=True)
    features = Column(JSON, default=lambda: ["basic"])
    notes = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)

    # Relationship
    user = relationship("ToolUser", back_populates="tool_licenses")


# ==================== Database Functions ====================

def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database - create all tables"""
    Base.metadata.create_all(bind=engine)
    print("✅ Database initialized")
    seed_default_tools()
    load_tools_from_db()


def create_default_admin():
    """Create default admin user if not exists"""
    import bcrypt
    
    db = SessionLocal()
    try:
        # Check if admin exists
        admin = db.query(AdminUser).filter(AdminUser.username == "admin").first()
        if not admin:
            # Create default admin
            default_password = "admin123"  # Change this!
            # Hash password with bcrypt
            password_hash = bcrypt.hashpw(default_password.encode(), bcrypt.gensalt()).decode()
            
            admin = AdminUser(
                username="admin",
                email="admin@epchannel.codes",
                password_hash=password_hash,
                is_superuser=True
            )
            db.add(admin)
            db.commit()
            print(f"✅ Default admin created: admin / {default_password}")
            print("⚠️  PLEASE CHANGE DEFAULT PASSWORD!")
        else:
            print("✅ Admin user already exists")
    finally:
        db.close()


def migrate_existing_licenses():
    """Migrate licenses from in-memory dict to database"""
    from main import LICENSE_DATABASE
    from datetime import datetime
    
    db = SessionLocal()
    try:
        for key, data in LICENSE_DATABASE.items():
            # Check if license already exists
            existing = db.query(License).filter(License.license_key == key).first()
            if not existing:
                license_obj = License(
                    license_key=key,
                    device_id=data.get("device_id"),
                    active=data.get("active", True),
                    expire_at=datetime.fromisoformat(data.get("expire_at")),
                    features=data.get("features", []),
                    max_devices=data.get("max_devices", 1)
                )
                db.add(license_obj)
        
        db.commit()
        print("✅ Licenses migrated to database")
    except Exception as e:
        print(f"⚠️  Migration error: {e}")
    finally:
        db.close()


# ==================== Helper Functions ====================

def get_license_by_key(db: Session, license_key: str) -> Optional[License]:
    """Get license by key"""
    return db.query(License).filter(License.license_key == license_key).first()


def create_license(db: Session, license_data: Dict[str, Any]) -> License:
    """Create new license"""
    license_obj = License(**license_data)
    db.add(license_obj)
    db.commit()
    db.refresh(license_obj)
    return license_obj


def update_license(db: Session, license_key: str, update_data: Dict[str, Any]) -> Optional[License]:
    """Update license"""
    license_obj = get_license_by_key(db, license_key)
    if license_obj:
        for key, value in update_data.items():
            setattr(license_obj, key, value)
        db.commit()
        db.refresh(license_obj)
    return license_obj


def delete_license(db: Session, license_key: str) -> bool:
    """Delete license"""
    license_obj = get_license_by_key(db, license_key)
    if license_obj:
        db.delete(license_obj)
        db.commit()
        return True
    return False


def log_license_activity(
    db: Session,
    license_key: str,
    action: str,
    status: str,
    message: str = None,
    device_id: str = None,
    ip_address: str = None
):
    """Log license activity"""
    log = LicenseLog(
        license_key=license_key,
        device_id=device_id,
        action=action,
        status=status,
        message=message,
        ip_address=ip_address
    )
    db.add(log)
    db.commit()


def get_stats(db: Session, days: int = 30) -> Dict[str, Any]:
    """Get system statistics"""
    from sqlalchemy import func
    from datetime import datetime, timedelta
    
    now = datetime.utcnow()
    start_date = now - timedelta(days=days)
    
    # License counts
    total_licenses = db.query(func.count(License.id)).scalar()
    active_licenses = db.query(func.count(License.id)).filter(
        License.active == True,
        License.expire_at > now
    ).scalar()
    expired_licenses = db.query(func.count(License.id)).filter(
        License.expire_at <= now
    ).scalar()
    
    # Activity counts (last N days)
    verify_logs = db.query(func.count(LicenseLog.id)).filter(
        LicenseLog.action == "verify",
        LicenseLog.created_at >= start_date
    ).scalar()
    
    heartbeat_logs = db.query(func.count(LicenseLog.id)).filter(
        LicenseLog.action == "heartbeat",
        LicenseLog.created_at >= start_date
    ).scalar()
    
    return {
        "total_licenses": total_licenses,
        "active_licenses": active_licenses,
        "expired_licenses": expired_licenses,
        "inactive_licenses": total_licenses - active_licenses - expired_licenses,
        "verify_requests": verify_logs,
        "heartbeat_requests": heartbeat_logs,
        "period_days": days
    }


# ==================== Tool User CRUD ====================

def generate_tool_license_key(prefix: str = "EPMMO", key_prefix: str = "") -> str:
    """Generate a tool license key like EPMMO-VER-A1B2C3D4-E5F6G7H8"""
    random_part = secrets.token_hex(8).upper()
    if key_prefix:
        return f"{prefix}-{key_prefix}-{random_part[:8]}-{random_part[8:16]}"
    return f"{prefix}-{random_part[:8]}-{random_part[8:16]}"


def create_tool_user(db: Session, data: Dict[str, Any]) -> ToolUser:
    """Create a new tool user"""
    user = ToolUser(**data)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_tool_user(db: Session, user_id: int) -> Optional[ToolUser]:
    return db.query(ToolUser).filter(ToolUser.id == user_id).first()


def get_tool_user_by_email(db: Session, email: str) -> Optional[ToolUser]:
    return db.query(ToolUser).filter(ToolUser.email == email).first()


def get_all_tool_users(db: Session, skip: int = 0, limit: int = 100) -> List[ToolUser]:
    return db.query(ToolUser).offset(skip).limit(limit).all()


def update_tool_user(db: Session, user_id: int, data: Dict[str, Any]) -> Optional[ToolUser]:
    user = get_tool_user(db, user_id)
    if user:
        for key, value in data.items():
            setattr(user, key, value)
        user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(user)
    return user


def delete_tool_user(db: Session, user_id: int) -> bool:
    user = get_tool_user(db, user_id)
    if user:
        db.delete(user)
        db.commit()
        return True
    return False


# ==================== Tool License CRUD ====================

def create_tool_license(db: Session, data: Dict[str, Any]) -> ToolLicense:
    tool_code = data.get("tool_code", "")
    tool_info = AVAILABLE_TOOLS.get(tool_code, {})
    prefix = tool_info.get("prefix", "EPMMO")
    key_prefix = tool_info.get("key_prefix", "")
    if "license_key" not in data or not data["license_key"]:
        data["license_key"] = generate_tool_license_key(prefix, key_prefix)
    if "features" not in data:
        data["features"] = ["basic"]
    lic = ToolLicense(**data)
    db.add(lic)
    db.commit()
    db.refresh(lic)
    return lic


def get_tool_license_by_key(db: Session, license_key: str) -> Optional[ToolLicense]:
    return db.query(ToolLicense).filter(ToolLicense.license_key == license_key).first()


def get_tool_licenses_for_user(db: Session, user_id: int) -> List[ToolLicense]:
    return db.query(ToolLicense).filter(ToolLicense.user_id == user_id).all()


def get_all_tool_licenses(db: Session, tool_code: Optional[str] = None) -> List[ToolLicense]:
    query = db.query(ToolLicense)
    if tool_code:
        query = query.filter(ToolLicense.tool_code == tool_code)
    return query.all()


def update_tool_license(db: Session, license_id: int, data: Dict[str, Any]) -> Optional[ToolLicense]:
    lic = db.query(ToolLicense).filter(ToolLicense.id == license_id).first()
    if lic:
        for key, value in data.items():
            setattr(lic, key, value)
        db.commit()
        db.refresh(lic)
    return lic


def delete_tool_license(db: Session, license_id: int) -> bool:
    lic = db.query(ToolLicense).filter(ToolLicense.id == license_id).first()
    if lic:
        db.delete(lic)
        db.commit()
        return True
    return False


def verify_tool_license(
    db: Session, tool_code: str = None, license_key: str = "",
    device_id: str = None, device_name: str = None,
    ip_address: str = None
) -> Dict[str, Any]:
    """Verify a tool license key. If tool_code is None, auto-detect from the key."""
    # Find the license key
    lic_any = db.query(ToolLicense).filter(
        ToolLicense.license_key == license_key
    ).first()

    if not lic_any:
        return {"valid": False, "message": "Key bản quyền không hợp lệ"}

    # Check if the license is for the correct tool (only when tool_code is specified)
    if tool_code is not None and lic_any.tool_code != tool_code:
        return {
            "valid": False,
            "message": f"Key không thuộc tool: {tool_code}"
        }

    lic = lic_any

    if not lic.active:
        return {"valid": False, "message": "Bản quyền đã bị vô hiệu hóa"}

    if datetime.utcnow() > lic.expire_at:
        return {
            "valid": False,
            "message": "Bản quyền đã hết hạn",
            "expire_at": lic.expire_at.isoformat()
        }

    # Device binding
    if device_id:
        if lic.device_id is None:
            lic.device_id = device_id
            if device_name:
                lic.device_name = device_name
        elif lic.device_id != device_id:
            return {"valid": False, "message": "Key đã được gán cho thiết bị khác"}
        else:
            # Same device, update name if provided
            if device_name and device_name != lic.device_name:
                lic.device_name = device_name

    lic.use_count += 1
    lic.last_used_at = datetime.utcnow()
    if ip_address:
        lic.ip_address = ip_address
    db.commit()

    user = get_tool_user(db, lic.user_id)

    return {
        "valid": True,
        "expire_at": lic.expire_at.isoformat(),
        "features": lic.features or ["basic"],
        "message": "Xác minh bản quyền thành công",
        "user_name": user.name if user else None,
        "user_email": user.email if user else None,
        "tool_code": lic.tool_code
    }


if __name__ == "__main__":
    print("Initializing database...")
    init_db()
    create_default_admin()

    # Uncomment to migrate existing licenses
    # migrate_existing_licenses()

    print("\n✅ Database setup complete!")

