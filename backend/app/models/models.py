# app/models/models.py

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON, Enum, BigInteger
from sqlalchemy.orm import relationship
from app.core.database import Base
from datetime import datetime
import enum

class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    EXPIRED = "expired"

class ProtocolType(str, enum.Enum):
    SSH = "ssh"
    L2TP = "l2tp"
    IKEV2 = "ikev2"
    CISCO = "cisco"
    WIREGUARD = "wireguard"
    SHADOWSOCKS = "shadowsocks"
    TUIC = "tuic"
    VLESS = "vless"
    HYSTERIA2 = "hysteria2"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email = Column(String, unique=True, index=True, nullable=True)
    status = Column(Enum(UserStatus), default=UserStatus.ACTIVE)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    data_limit = Column(BigInteger, nullable=True)  # in bytes
    notes = Column(String, nullable=True)

    # Relationships
    protocols = relationship("UserProtocol", back_populates="user")
    connections = relationship("Connection", back_populates="user")
    bandwidth_usage = relationship("BandwidthUsage", back_populates="user")

class UserProtocol(Base):
    __tablename__ = "user_protocols"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    protocol = Column(Enum(ProtocolType))
    config = Column(JSON)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="protocols")

class Connection(Base):
    __tablename__ = "connections"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    protocol = Column(Enum(ProtocolType))
    ip_address = Column(String)
    location = Column(String, nullable=True)
    connected_at = Column(DateTime, default=datetime.utcnow)
    disconnected_at = Column(DateTime, nullable=True)
    bytes_sent = Column(BigInteger, default=0)
    bytes_received = Column(BigInteger, default=0)
    client_version = Column(String, nullable=True)
    device_type = Column(String, nullable=True)
    os = Column(String, nullable=True)

    # Relationships
    user = relationship("User", back_populates="connections")

class BandwidthUsage(Base):
    __tablename__ = "bandwidth_usage"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    protocol = Column(Enum(ProtocolType))
    timestamp = Column(DateTime, default=datetime.utcnow)
    bytes_sent = Column(BigInteger, default=0)
    bytes_received = Column(BigInteger, default=0)

    # Relationships
    user = relationship("User", back_populates="bandwidth_usage")

class SystemSettings(Base):
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)
    value = Column(JSON)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ProtocolSettings(Base):
    __tablename__ = "protocol_settings"

    id = Column(Integer, primary_key=True, index=True)
    protocol = Column(Enum(ProtocolType), unique=True)
    port = Column(Integer)
    config = Column(JSON)
    enabled = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Backup(Base):
    __tablename__ = "backups"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String)
    size = Column(BigInteger)
    checksum = Column(String)
    components = Column(JSON)  # Which components were backed up
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String)  # 'completed', 'failed', etc.
    notes = Column(String, nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    ip_address = Column(String, nullable=True)
    details = Column(JSON)
