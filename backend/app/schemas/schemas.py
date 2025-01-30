from typing import Optional, List
from pydantic import BaseModel, EmailStr
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: Optional[EmailStr] = None
    is_active: bool = True
    protocol: str
    expires_at: Optional[datetime] = None

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    protocol: Optional[str] = None
    expires_at: Optional[datetime] = None

class User(UserBase):
    id: int
    created_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class SystemStats(BaseModel):
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    active_users: int
    total_connections: int
    uptime: str

class BandwidthStats(BaseModel):
    incoming: float
    outgoing: float
    total: float
    history: List[dict]

class ProtocolStats(BaseModel):
    protocol: str
    online_users: int
    port: int
    incoming_traffic: str
    outgoing_traffic: str
    uptime: str

class Settings(BaseModel):
    maintenance_mode: bool = False
    backup_enabled: bool = True
    backup_interval: int = 24
    monitoring_interval: int = 5
    max_users: int = 1000
    default_user_expire_days: int = 30

    class Config:
        json_encoders = {
            datetime: lambda v: v.strftime("%Y-%m-%d %H:%M:%S")
        }
