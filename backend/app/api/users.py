# app/api/users.py

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from app.core.database import get_db
from app.core.logger import logger, log_audit
from app.models import User, UserProtocol, Connection, BandwidthUsage
from app.schemas.user import (
    UserList, UserDetail, UserCreate, UserUpdate,
    UserStats, ProtocolConfig, ConnectionInfo
)
from app.api.deps import get_current_active_user

router = APIRouter()

@router.get("/", response_model=List[UserList])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    protocol: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    sort: Optional[str] = "username",
    order: Optional[str] = "asc",
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all users with filtering and pagination"""
    query = db.query(User)

    # Apply filters
    if protocol:
        query = query.join(UserProtocol).filter(UserProtocol.protocol == protocol)
    if status:
        query = query.filter(User.status == status)
    if search:
        query = query.filter(User.username.ilike(f"%{search}%"))

    # Apply sorting
    if order == "asc":
        query = query.order_by(getattr(User, sort))
    else:
        query = query.order_by(getattr(User, sort).desc())

    total = query.count()
    users = query.offset(skip).limit(limit).all()

    return {
        "total": total,
        "items": users,
        "page": skip // limit + 1,
        "pages": (total + limit - 1) // limit
    }

@router.get("/online", response_model=List[ConnectionInfo])
async def list_online_users(
    protocol: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all currently connected users"""
    query = db.query(Connection).filter(Connection.disconnected_at == None)
    
    if protocol:
        query = query.filter(Connection.protocol == protocol)
    
    connections = query.all()
    return connections

@router.get("/{user_id}", response_model=UserDetail)
async def get_user(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get detailed user information"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("/", response_model=UserDetail)
async def create_user(
    user: UserCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new user"""
    # Check if user exists
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create user
    db_user = User(**user.dict(exclude={'protocols'}))
    db.add(db_user)
    db.flush()

    # Add protocol configurations
    for protocol in user.protocols:
        protocol_config = UserProtocol(
            user_id=db_user.id,
            protocol=protocol.protocol,
            config=protocol.config
        )
        db.add(protocol_config)

    db.commit()
    db.refresh(db_user)

    log_audit("user_created", current_user.id, f"Created user {user.username}")
    return db_user

@router.put("/{user_id}", response_model=UserDetail)
async def update_user(
    user_id: int,
    user: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update user information"""
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update user fields
    for key, value in user.dict(exclude_unset=True).items():
        if hasattr(db_user, key):
            setattr(db_user, key, value)

    db.commit()
    db.refresh(db_user)

    log_audit("user_updated", current_user.id, f"Updated user {db_user.username}")
    return db_user

@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete a user"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Store username for logging
    username = user.username

    db.delete(user)
    db.commit()

    log_audit("user_deleted", current_user.id, f"Deleted user {username}")
    return {"message": "User deleted successfully"}

@router.get("/{user_id}/stats", response_model=UserStats)
async def get_user_stats(
    user_id: int,
    period: str = Query("24h", regex="^(1h|24h|7d|30d)$"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get user statistics"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Calculate period start time
    period_map = {
        "1h": timedelta(hours=1),
        "24h": timedelta(days=1),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30)
    }
    start_time = datetime.utcnow() - period_map[period]

    # Get bandwidth usage
    bandwidth = db.query(BandwidthUsage).filter(
        BandwidthUsage.user_id == user_id,
        BandwidthUsage.timestamp >= start_time
    ).all()

    # Calculate statistics
    total_received = sum(b.bytes_received for b in bandwidth)
    total_sent = sum(b.bytes_sent for b in bandwidth)
    
    # Get active connections
    active_connections = db.query(Connection).filter(
        Connection.user_id == user_id,
        Connection.disconnected_at == None
    ).all()

    # Get protocol usage
    protocol_usage = {}
    for protocol in user.protocols:
        usage = db.query(BandwidthUsage).filter(
            BandwidthUsage.user_id == user_id,
            BandwidthUsage.protocol == protocol.protocol,
            BandwidthUsage.timestamp >= start_time
        ).all()
        
        protocol_usage[protocol.protocol] = {
            'bytes_sent': sum(u.bytes_sent for u in usage),
            'bytes_received': sum(u.bytes_received for u in usage)
        }

    return {
        'user_id': user_id,
        'username': user.username,
        'period': period,
        'start_time': start_time,
        'end_time': datetime.utcnow(),
        'total_bytes_received': total_received,
        'total_bytes_sent': total_sent,
        'active_connections': len(active_connections),
        'protocol_usage': protocol_usage,
        'data_limit': user.data_limit,
        'data_used': total_received + total_sent,
        'data_remaining': user.data_limit - (total_received + total_sent) if user.data_limit else None
    }

@router.post("/{user_id}/protocols", response_model=ProtocolConfig)
async def add_user_protocol(
    user_id: int,
    protocol: ProtocolConfig,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Add a new protocol configuration for user"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if protocol already exists
    existing = db.query(UserProtocol).filter(
        UserProtocol.user_id == user_id,
        UserProtocol.protocol == protocol.protocol
    ).first()

    if existing:
        raise HTTPException(status_code=400, detail="Protocol already configured for user")

    protocol_config = UserProtocol(
        user_id=user_id,
        protocol=protocol.protocol,
        config=protocol.config
    )
    db.add(protocol_config)
    db.commit()
    db.refresh(protocol_config)

    log_audit(
        "protocol_added",
        current_user.id,
        f"Added {protocol.protocol} for user {user.username}"
    )
    return protocol_config

@router.delete("/{user_id}/protocols/{protocol}")
async def remove_user_protocol(
    user_id: int,
    protocol: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Remove a protocol configuration from user"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    protocol_config = db.query(UserProtocol).filter(
        UserProtocol.user_id == user_id,
        UserProtocol.protocol == protocol
    ).first()

    if not protocol_config:
        raise HTTPException(status_code=404, detail="Protocol not found")

    db.delete(protocol_config)
    db.commit()

    log_audit(
        "protocol_removed",
        current_user.id,
        f"Removed {protocol} from user {user.username}"
    )
    return {"message": "Protocol removed successfully"}

@router.post("/{user_id}/reset-traffic")
async def reset_user_traffic(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Reset user traffic statistics"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Delete bandwidth usage records
    db.query(BandwidthUsage).filter(BandwidthUsage.user_id == user_id).delete()
    db.commit()

    log_audit(
        "traffic_reset",
        current_user.id,
        f"Reset traffic stats for user {user.username}"
    )
    return {"message": "Traffic statistics reset successfully"}

@router.post("/{user_id}/disconnect")
async def disconnect_user(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Disconnect all active user connections"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Mark all active connections as disconnected
    active_connections = db.query(Connection).filter(
        Connection.user_id == user_id,
        Connection.disconnected_at == None
    ).all()

    for conn in active_connections:
        conn.disconnected_at = datetime.utcnow()

    db.commit()

    log_audit(
        "user_disconnected",
        current_user.id,
        f"Disconnected all sessions for user {user.username}"
    )
    return {"message": "User disconnected successfully"}

@router.get("/{user_id}/connections", response_model=List[ConnectionInfo])
async def get_user_connections(
    user_id: int,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get user connection history"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    connections = db.query(Connection).filter(
        Connection.user_id == user_id
    ).order_by(Connection.connected_at.desc()).limit(limit).all()

    return connections
