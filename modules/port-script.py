#!/usr/bin/env python3

import os
import sys
import yaml
import asyncio
import logging
import subprocess
import shutil
from typing import Dict, Any, List, Optional, Union, Tuple, TypeVar, Generic
from dataclasses import dataclass, field
from pathlib import Path
import tempfile
import json
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps

# Core ML and Data Science
import tensorflow as tf
import torch
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
import xgboost as xgb
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import Dense, Dropout, LSTM, Conv1D, BatchNormalization
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
import tensorflow_federated as tff

# Network and System
import socket
import requests
import speedtest
import psutil
import scapy.all as scapy
import paramiko
import netaddr
import grpc
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import aiohttp
import asyncssh
import ansible_runner
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
from ansible.vars.manager import VariableManager
from ansible.playbook.play import Play
from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.plugins.callback import CallbackBase

# Database and ORM
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import QueuePool
from sqlalchemy.engine import make_url
import alembic.config
from prisma import Prisma
from prisma.models import User, VPNConfiguration, NetworkMetrics
import asyncpg
from tenacity import retry, stop_after_attempt, wait_exponential

# Security and Authentication
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import jwt
from passlib.hash import argon2
from authlib.integrations.base_client import OAuthError
from authlib.oauth2.rfc7636 import create_s256_code_challenge

# Kubernetes Integration
from kubernetes import client, config, watch
from kubernetes.client import ApiClient
from kubernetes.stream import stream

# Configuration and Environment
from dotenv import load_dotenv
import configargparse
from typing_extensions import Annotated
import pydantic
from pydantic import BaseModel, Field, validator
from pydantic.json import pydantic_encoder

# Monitoring and Observability
from opentelemetry import trace, metrics
from opentelemetry.exporter.otlp.proto.grpc import trace_exporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import start_http_server, Summary, Counter, Gauge, Histogram
import grafana_client
from elasticapm import Client as ElasticAPMClient

# Advanced Logging
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn
import structlog

# Web Framework
from fastapi import FastAPI, HTTPException, Depends, Security, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.throttling import ThrottlingMiddleware

# System Resource Management
import resource
import multiprocessing

# Load environment variables
load_dotenv()

# Advanced Configuration Models with Validation
class ConnectionPoolConfig(BaseModel):
    max_connections: int = Field(default=20, ge=5)
    min_connections: int = Field(default=5, ge=1)
    max_overflow: int = Field(default=10, ge=0)
    timeout: float = Field(default=30.0, ge=5.0)
    retry_limit: int = Field(default=3, ge=1)
    retry_interval: float = Field(default=1.0, ge=0.1)
    
    class Config:
        extra = "forbid"

class ResourceManagementConfig(BaseModel):
    cpu_limit_percent: float = Field(default=80.0, ge=20.0, le=95.0)
    memory_limit_percent: float = Field(default=85.0, ge=20.0, le=95.0)
    storage_limit_percent: float = Field(default=90.0, ge=20.0, le=95.0)
    min_free_memory_mb: int = Field(default=512, ge=256)
    connection_limit_per_protocol: int = Field(default=100, ge=10)
    
    class Config:
        extra = "forbid"

class SecurityConfig(BaseModel):
    encryption_algorithm: str = Field(default="AES-256-GCM")
    key_rotation_days: int = Field(default=30, ge=1, le=90)
    certificate_validity_days: int = Field(default=365, ge=30)
    min_password_length: int = Field(default=12, ge=8)
    max_login_attempts: int = Field(default=3, ge=1)
    session_timeout_minutes: int = Field(default=30, ge=5)
    jwt_secret: str = Field(default_factory=lambda: os.urandom(32).hex())
    rate_limit_requests: int = Field(default=100, ge=10)
    rate_limit_minutes: int = Field(default=1, ge=1)
    
    @validator('encryption_algorithm')
    def validate_encryption_algorithm(cls, v):
        allowed_algorithms = ["AES-256-GCM", "ChaCha20-Poly1305"]
        if v not in allowed_algorithms:
            raise ValueError(f"Algorithm must be one of {allowed_algorithms}")
        return v
    
    class Config:
        extra = "forbid"

class MLConfig(BaseModel):
    model_type: str = Field(default="hybrid")
    batch_size: int = Field(default=32, ge=1)
    learning_rate: float = Field(default=0.001, gt=0)
    epochs: int = Field(default=100, ge=1)
    validation_split: float = Field(default=0.2, ge=0.1, le=0.3)
    early_stopping_patience: int = Field(default=10, ge=1)
    model_checkpoint_path: str = Field(default="/var/lib/vpn_intelligence/ml_models")
    
    class Config:
        extra = "forbid"

class NetworkConfig(BaseModel):
    protocols: List[str] = Field(default_factory=lambda: ["WireGuard", "OpenVPN", "IPSec"])
    port_ranges: Dict[str, List[int]] = Field(default_factory=dict)
    bandwidth_threshold_mbps: float = Field(default=100.0, ge=0)
    latency_threshold_ms: float = Field(default=50.0, ge=0)
    monitoring_interval_seconds: int = Field(default=60, ge=30)
    protocol_specific_checks: Dict[str, List[str]] = Field(default_factory=dict)
    
    class Config:
        extra = "forbid"

class AnsibleConfig(BaseModel):
    playbook_dir: str = Field(default="/etc/vpn_intelligence/playbooks")
    inventory_file: str = Field(default="/etc/vpn_intelligence/inventory.yml")
    roles_path: str = Field(default="/etc/vpn_intelligence/roles")
    extra_vars: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        extra = "forbid"

class VPNIntelligenceConfig(BaseModel):
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    ml: MLConfig = Field(default_factory=MLConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    ansible: AnsibleConfig = Field(default_factory=AnsibleConfig)
    connection_pool: ConnectionPoolConfig = Field(default_factory=ConnectionPoolConfig)
    resource_management: ResourceManagementConfig = Field(default_factory=ResourceManagementConfig)
    environment: str = Field(default="production")
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    database_url: str = Field(default="postgresql://localhost:5432/vpn_intelligence")
    
    class Config:
        extra = "forbid"

# Enhanced Database Models with Relations
Base = declarative_base()

class ResourceMetrics(Base):
    __tablename__ = "resource_metrics"
    
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp = sa.Column(sa.DateTime, default=datetime.utcnow)
    cpu_usage = sa.Column(sa.Float)
    memory_usage = sa.Column(sa.Float)
    storage_usage = sa.Column(sa.Float)
    active_connections = sa.Column(sa.Integer)
    server_id = sa.Column(sa.Integer, sa.ForeignKey('servers.id'))
    
    server = relationship("Server", back_populates="resource_metrics")

class NetworkMetrics(Base):
    __tablename__ = "network_metrics"
    
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp = sa.Column(sa.DateTime, default=datetime.utcnow)
    protocol = sa.Column(sa.String(50))
    latency_ms = sa.Column(sa.Float)
    bandwidth_mbps = sa.Column(sa.Float)
    packet_loss = sa.Column(sa.Float)
    cpu_usage = sa.Column(sa.Float)
    memory_usage = sa.Column(sa.Float)
    active_connections = sa.Column(sa.Integer)
    server_id = sa.Column(sa.Integer, sa.ForeignKey('servers.id'))
    
    server = relationship("Server", back_populates="metrics")
    
    __table_args__ = (
        sa.Index('idx_timestamp', 'timestamp'),
        sa.Index('idx_protocol', 'protocol'),
        sa.Index('idx_server_timestamp', 'server_id', 'timestamp'),
    )

class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = sa.Column(sa.Integer, primary_key=True)
    timestamp = sa.Column(sa.DateTime, default=datetime.utcnow)
    event_type = sa.Column(sa.String(100))
    severity = sa.Column(sa.String(20))
    description = sa.Column(sa.Text)
    source_ip = sa.Column(sa.String(45))
    user_id = sa.Column(sa.Integer, sa.ForeignKey('users.id'))
    
    user = relationship("User", back_populates="security_events")
    
    __table_args__ = (
        sa.Index('idx_timestamp_severity', 'timestamp', 'severity'),
        sa.Index('idx_user_timestamp', 'user_id', 'timestamp'),
    )

class Server(Base):
    __tablename__ = "servers"
    
    id = sa.Column(sa.Integer, primary_key=True)
    hostname = sa.Column(sa.String(255), unique=True)
    ip_address = sa.Column(sa.String(45))
    status = sa.Column(sa.String(20))
    last_seen = sa.Column(sa.DateTime, default=datetime.utcnow)
    total_cpu_cores = sa.Column(sa.Integer)
    total_memory_mb = sa.Column(sa.Integer)
    total_storage_gb = sa.Column(sa.Integer)
    
    metrics = relationship("NetworkMetrics", back_populates="server")
    resource_metrics = relationship("ResourceMetrics", back_populates="server")
    vpn_configs = relationship("VPNConfiguration", back_populates="server")

class VPNConfiguration(Base):
    __tablename__ = "vpn_configurations"
    
    id = sa.Column(sa.Integer, primary_key=True)
    protocol = sa.Column(sa.String(50))
    config_data = sa.Column(sa.JSON)
    server_id = sa.Column(sa.Integer, sa.ForeignKey('servers.id'))
    created_at = sa.Column(sa.DateTime, default=datetime.utcnow)
    updated_at = sa.Column(sa.DateTime, onupdate=datetime.utcnow)
    max_connections = sa.Column(sa.Integer)
    resource_allocation = sa.Column(sa.JSON)
    
    server = relationship("Server", back_populates="vpn_configs")

# Resource Management Service
class ResourceManager:
    def __init__(self, config: ResourceManagementConfig):
        self.config = config
        self.resource_metrics = Counter('resource_usage', 'Resource usage metrics', ['type'])
        self.connection_gauge = Gauge('active_connections', 'Active connections', ['protocol'])
    
    async def check_resources(self, server: Server) -> Dict[str, bool]:
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        self.resource_metrics.labels(type='cpu').inc(cpu_percent)
        self.resource_metrics.labels(type='memory').inc(memory.percent)
        self.resource_metrics.labels(type='disk').inc(disk.percent)
        
        return {
            'cpu_ok': cpu_percent < self.config.cpu_limit_percent,
            'memory_ok': memory.percent < self.config.memory_limit_percent,
            'storage_ok': disk.percent < self.config.storage_limit_percent,
            'memory_free_ok': memory.available / (1024 * 1024) > self.config.min_free_memory_mb
        }
    
    async def allocate_resources(self, server: Server, protocol: str) -> Dict[str, Any]:
        resources = await self.check_resources(server)
        if not all(resources.values()):
            raise ResourceError("Insufficient server resources")
        
        # Calculate resource allocation based on server capacity
        total_memory = server.total_memory_mb
        total_cpu = server.total_cpu_cores
        
        # Allocate resources per protocol
        allocation = {
            'cpu_cores': max(0.25, total_cpu * 0.2),  # Minimum 0.25 core, max 20% of total
            'memory_mb': max(256, total_memory * 0.15),  # Minimum 256MB, max 15% of total
            'max_connections': self.config.connection_limit_per_protocol
        }
        
        return allocation

# Enhanced Connection Pool Management
class ConnectionPoolManager:
    def __init__(self, config: ConnectionPoolConfig):
        self.config = config
        self.engine = None
        self._connection_attempts = 0
        self._pool_metrics = {
            'active_connections': 0,
            'pool_capacity': config.pool_size,
            'connection_timeouts': 0,
            'failed_connections': 0
        }
        self._setup_monitoring()
        
    async def initialize(self):
        """Initialize the connection pool with retry logic and monitoring."""
        while self._connection_attempts < self.config.max_retries:
            try:
                self.engine = create_async_engine(
                    self.config.database_url,
                    pool_size=self.config.pool_size,
                    max_overflow=self.config.max_overflow,
                    pool_timeout=self.config.pool_timeout,
                    pool_recycle=self.config.pool_recycle,
                    pool_pre_ping=True,
                    echo=self.config.debug
                )
                
                # Test the connection
                async with self.engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
                break
                
            except Exception as e:
                self._connection_attempts += 1
                self._pool_metrics['failed_connections'] += 1
                
                if self._connection_attempts >= self.config.max_retries:
                    raise ConnectionError(f"Failed to initialize connection pool after {self.config.max_retries} attempts") from e
                
                await asyncio.sleep(self.config.retry_delay)
    
    def _setup_monitoring(self):
        """Setup monitoring metrics for the connection pool."""
        self.metrics = {
            'active_connections': Gauge(
                'db_active_connections',
                'Number of active database connections'
            ),
            'connection_timeouts': Counter(
                'db_connection_timeouts_total',
                'Total number of connection timeouts'
            ),
            'failed_connections': Counter(
                'db_failed_connections_total',
                'Total number of failed connection attempts'
            ),
            'pool_usage': Gauge(
                'db_pool_usage_ratio',
                'Ratio of used connections to pool capacity'
            )
        }

    async def get_session(self) -> AsyncSession:
        """Get a session from the pool with monitoring and error handling."""
        try:
            if not self.engine:
                await self.initialize()
            
            session = sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )()
            
            self._pool_metrics['active_connections'] += 1
            self.metrics['active_connections'].set(self._pool_metrics['active_connections'])
            self.metrics['pool_usage'].set(
                self._pool_metrics['active_connections'] / self._pool_metrics['pool_capacity']
            )
            
            return session
            
        except asyncio.TimeoutError:
            self._pool_metrics['connection_timeouts'] += 1
            self.metrics['connection_timeouts'].inc()
            raise ConnectionPoolTimeoutError("Failed to acquire database connection from pool")

    async def release_session(self, session: AsyncSession):
        """Release a session back to the pool."""
        try:
            await session.close()
            self._pool_metrics['active_connections'] -= 1
            self.metrics['active_connections'].set(self._pool_metrics['active_connections'])
            self.metrics['pool_usage'].set(
                self._pool_metrics['active_connections'] / self._pool_metrics['pool_capacity']
            )
        except Exception as e:
            logger.error(f"Error releasing database session: {e}")
            raise

class ResourceManager:
    def __init__(self, config: ResourceConfig):
        self.config = config
        self.resource_metrics = {
            'cpu_usage': Gauge('server_cpu_usage', 'CPU usage percentage'),
            'memory_usage': Gauge('server_memory_usage', 'Memory usage percentage'),
            'disk_usage': Gauge('server_disk_usage', 'Disk usage percentage'),
            'network_bandwidth': Gauge('server_network_bandwidth', 'Network bandwidth usage'),
            'vpn_connections': Gauge('vpn_active_connections', 'Number of active VPN connections')
        }
        self.resource_limits = {
            'cpu_threshold': 85.0,  # 85% CPU usage threshold
            'memory_threshold': 90.0,  # 90% memory usage threshold
            'disk_threshold': 85.0,  # 85% disk usage threshold
            'connections_per_cpu': 50  # Maximum VPN connections per CPU core
        }
        
    async def check_resources(self) -> Dict[str, float]:
        """Check current resource usage and update metrics."""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        metrics = {
            'cpu_usage': cpu_percent,
            'memory_usage': memory.percent,
            'disk_usage': disk.percent,
            'available_memory': memory.available / (1024 * 1024)  # MB
        }
        
        # Update Prometheus metrics
        self.resource_metrics['cpu_usage'].set(cpu_percent)
        self.resource_metrics['memory_usage'].set(memory.percent)
        self.resource_metrics['disk_usage'].set(disk.percent)
        
        return metrics
    
    async def can_start_protocol(self, protocol: str) -> Tuple[bool, str]:
        """Check if there are sufficient resources to start a new protocol."""
        metrics = await self.check_resources()
        
        protocol_requirements = {
            'WireGuard': {'cpu': 5.0, 'memory': 256},  # MB
            'OpenVPN': {'cpu': 10.0, 'memory': 512},   # MB
            'IPSec': {'cpu': 15.0, 'memory': 384}      # MB
        }
        
        req = protocol_requirements.get(protocol, {'cpu': 10.0, 'memory': 384})
        
        if metrics['cpu_usage'] + req['cpu'] > self.resource_limits['cpu_threshold']:
            return False, f"CPU usage would exceed threshold ({metrics['cpu_usage']}%)"
            
        if metrics['memory_usage'] + (req['memory'] / metrics['available_memory']) * 100 > self.resource_limits['memory_threshold']:
            return False, "Insufficient memory available"
            
        return True, "Resources available"

    async def monitor_protocol_health(self, protocol: str) -> Dict[str, Any]:
        """Monitor protocol-specific health metrics."""
        health_checks = {
            'WireGuard': self._check_wireguard_health,
            'OpenVPN': self._check_openvpn_health,
            'IPSec': self._check_ipsec_health
        }
        
        check_func = health_checks.get(protocol)
        if check_func:
            return await check_func()
        return {"status": "unknown", "message": f"No health check defined for {protocol}"}

    async def _check_wireguard_health(self) -> Dict[str, Any]:
        """Check WireGuard-specific health metrics."""
        try:
            result = await asyncio.create_subprocess_shell(
                "wg show all dump",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                return {
                    "status": "error",
                    "message": f"WireGuard check failed: {stderr.decode()}"
                }
            
            connections = len(stdout.decode().splitlines())
            self.resource_metrics['vpn_connections'].set(connections)
            
            return {
                "status": "healthy",
                "connections": connections,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"WireGuard health check failed: {e}")
            return {"status": "error", "message": str(e)}

    async def _check_openvpn_health(self) -> Dict[str, Any]:
        """Check OpenVPN-specific health metrics."""
        try:
            # Connect to OpenVPN management interface
            reader, writer = await asyncio.open_connection(
                '127.0.0.1',
                self.config.openvpn_mgmt_port
            )
            
            writer.write(b'status\n')
            await writer.drain()
            
            data = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            
            # Parse OpenVPN status
            status_lines = data.decode().splitlines()
            client_count = sum(1 for line in status_lines if "CONNECTED" in line)
            
            self.resource_metrics['vpn_connections'].set(client_count)
            
            return {
                "status": "healthy",
                "connections": client_count,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"OpenVPN health check failed: {e}")
            return {"status": "error", "message": str(e)}

    async def _check_ipsec_health(self) -> Dict[str, Any]:
        """Check IPSec-specific health metrics."""
        try:
            result = await asyncio.create_subprocess_shell(
                "ipsec status",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                return {
                    "status": "error",
                    "message": f"IPSec check failed: {stderr.decode()}"
                }
            
            # Parse IPSec status
            status_text = stdout.decode()
            connections = len([line for line in status_text.splitlines() if "ESTABLISHED" in line])
            
            self.resource_metrics['vpn_connections'].set(connections)
            
            return {
                "status": "healthy",
                "connections": connections,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"IPSec health check failed: {e}")
            return {"status": "error", "message": str(e)}

class RateLimiter:
    """Rate limiting implementation for API endpoints."""
    def __init__(self, rate_limit: int, time_window: int):
        self.rate_limit = rate_limit
        self.time_window = time_window
        self.tokens = {}
        self.last_check = {}
    
    async def is_allowed(self, key: str) -> bool:
        now = time.time()
        self.tokens.setdefault(key, self.rate_limit)
        self.last_check.setdefault(key, now)
        
        # Calculate token refill
        time_passed = now - self.last_check[key]
        self.tokens[key] = min(
            self.rate_limit,
            self.tokens[key] + (time_passed / self.time_window) * self.rate_limit
        )
        
        if self.tokens[key] >= 1:
            self.tokens[key] -= 1
            self.last_check[key] = now
            return True
        return False

class SecurityManager:
    """Enhanced security management with certificate rotation."""
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.cert_manager = CertificateManager(config)
        self.rate_limiter = RateLimiter(
            rate_limit=100,  # requests per window
            time_window=60   # seconds
        )
    
    async def rotate_certificates(self):
        """Implement certificate rotation logic."""
        try:
            new_cert = await self.cert_manager.generate_certificate()
            await self.cert_manager.backup_current_certificate()
            await self.cert_manager.deploy_certificate(new_cert)
            
            # Update all VPN configurations to use new certificate
            async with AsyncSession() as session:
                vpn_configs = await session.execute(
                    select(VPNConfiguration)
                )
                for config in vpn_configs.scalars():
                    config.config_data['certificate'] = new_cert.public_key
                    session.add(config)
                await session.commit()
                
        except Exception as e:
            logger.error(f"Certificate rotation failed: {e}")
            # Implement fallback mechanism
            await self.cert_manager.restore_backup_certificate()
            raise

class CertificateManager:
    """Handle certificate generation and management."""
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.cert_path = Path("/etc/vpn-intelligence/certs")
        self.backup_path = Path("/etc/vpn-intelligence/certs/backup")
        
    async def generate_certificate(self) -> Certificate:
        """Generate new SSL/TLS certificate."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"vpn-intelligence.local")
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=self.config.certificate_validity_days)
        ).sign(private_key, hashes.SHA256())
        
        return Certificate(cert, private_key)

    async def backup_current_certificate(self):
        """Backup current certificate before rotation."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_dir = self.backup_path / timestamp
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        for cert_file in self.cert_path.glob("*.pem"):
            shutil.copy2(cert_file, backup_dir / cert_file.name)

# Initialize and run the application
def main():
    # Load configuration
    config = VPNIntelligenceConfig()
    
    # Initialize managers
    connection_pool = ConnectionPoolManager(config.connection_pool)
    resource_manager = ResourceManager(config.resources)
    security_manager = SecurityManager(config.security)
    
    # Create FastAPI application
    app = FastAPI(
        title="VPN Intelligence System",
        description="Advanced VPN Management System with Resource Optimization",
        version="2.0.0"
    )
    
    # Add middleware for rate limiting
    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        client_ip = request.client.host
        if not await security_manager.rate_limiter.is_allowed(client_ip):
            raise HTTPException(
                status_code=429,
                detail="Too many requests"
            )
        return await call_next(request)
    
    # Start application
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        ssl_keyfile="/etc/vpn-intelligence/certs/key.pem",
        ssl_certfile="/etc/vpn-intelligence/certs/cert.pem",
        workers=4,
        loop="uvloop"
    )

# Connection Pool Configuration
class DatabaseManager:
    def __init__(self, config: VPNIntelligenceConfig):
        self.config = config
        self.engine = None
        self.pool_initialized = False
        self._setup_connection_pool()

    def _setup_connection_pool(self):
        if not self.pool_initialized:
            self.engine = create_async_engine(
                self.config.database_url,
                pool_size=20,  # Maximum number of connections in pool
                max_overflow=10,  # Maximum number of connections that can be created beyond pool_size
                pool_timeout=30,  # Seconds to wait before giving up on getting a connection
                pool_recycle=1800,  # Recycle connections after 30 minutes
                pool_pre_ping=True,  # Enable connection health checks
                echo=self.config.debug
            )
            self.pool_initialized = True

    async def get_connection(self, retries: int = 3, backoff_factor: float = 0.5) -> AsyncSession:
        for attempt in range(retries):
            try:
                async_session = sessionmaker(
                    self.engine,
                    class_=AsyncSession,
                    expire_on_commit=False
                )
                return async_session()
            except Exception as e:
                if attempt == retries - 1:
                    raise
                await asyncio.sleep(backoff_factor * (2 ** attempt))

    async def close_pool(self):
        if self.engine:
            await self.engine.dispose()
            self.pool_initialized = False

# Enhanced Error Handling and Fallback Mechanism
class ServiceManagerError(Exception):
    pass

class ServiceDeploymentError(ServiceManagerError):
    pass

class ResourceValidationError(ServiceManagerError):
    pass

class FallbackManager:
    def __init__(self, service_manager: ServiceManager):
        self.service_manager = service_manager
        self.fallback_configs = {}
        self.retry_delay = 5  # seconds
        self.max_retries = 3

    async def execute_with_fallback(self, service_name: str, operation: callable, *args, **kwargs):
        for attempt in range(self.max_retries):
            try:
                return await operation(*args, **kwargs)
            except Exception as e:
                if attempt == self.max_retries - 1:
                    # If all retries failed, try fallback configuration
                    if service_name in self.fallback_configs:
                        return await self._apply_fallback(service_name)
                    raise ServiceDeploymentError(f"Operation failed after {self.max_retries} attempts: {str(e)}")
                await asyncio.sleep(self.retry_delay * (2 ** attempt))

    async def _apply_fallback(self, service_name: str):
        fallback_config = self.fallback_configs.get(service_name)
        if not fallback_config:
            raise ServiceDeploymentError(f"No fallback configuration available for {service_name}")
        
        try:
            return await self.service_manager.deploy_service(
                service_name,
                replicas=fallback_config.get('replicas', 1),
                config=fallback_config.get('config', {})
            )
        except Exception as e:
            raise ServiceDeploymentError(f"Fallback deployment failed: {str(e)}")

# Enhanced Security with Rate Limiting and Certificate Management
class SecurityManager:
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.rate_limiter = {}
        self.cert_manager = CertificateManager()

    async def rotate_certificates(self):
        while True:
            try:
                await self.cert_manager.rotate_certificates()
                await asyncio.sleep(self.config.key_rotation_days * 86400)
            except Exception as e:
                logging.error(f"Certificate rotation failed: {str(e)}")
                await asyncio.sleep(3600)  # Retry after an hour

    def check_rate_limit(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        if key not in self.rate_limiter:
            self.rate_limiter[key] = []
        
        # Clean up old entries
        self.rate_limiter[key] = [t for t in self.rate_limiter[key] if t > now - window]
        
        if len(self.rate_limiter[key]) >= limit:
            return False
        
        self.rate_limiter[key].append(now)
        return True

# Enhanced Resource Management
class ResourceManager:
    def __init__(self):
        self.resource_metrics = {}
        self.min_requirements = {
            'cpu_cores': 1,
            'ram_gb': 2,
            'storage_gb': 10
        }
        self.monitoring_interval = 30  # seconds

    async def monitor_resources(self):
        while True:
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')

                self.resource_metrics.update({
                    'cpu_usage': cpu_percent,
                    'memory_usage': memory.percent,
                    'memory_available': memory.available / (1024 ** 3),  # GB
                    'disk_usage': disk.percent,
                    'disk_available': disk.free / (1024 ** 3)  # GB
                })

                await self.store_metrics()
                await asyncio.sleep(self.monitoring_interval)
            except Exception as e:
                logging.error(f"Resource monitoring failed: {str(e)}")
                await asyncio.sleep(5)

    async def validate_resources(self, required_resources: Dict[str, float]) -> bool:
        current_resources = self.get_current_resources()
        
        if (current_resources['cpu_cores'] < required_resources.get('cpu_cores', self.min_requirements['cpu_cores']) or
            current_resources['ram_gb'] < required_resources.get('ram_gb', self.min_requirements['ram_gb']) or
            current_resources['storage_gb'] < required_resources.get('storage_gb', self.min_requirements['storage_gb'])):
            return False
        return True

    async def allocate_resources(self, service_name: str, resources: Dict[str, float]):
        if not await self.validate_resources(resources):
            raise ResourceValidationError("Insufficient system resources")

        # Update Kubernetes resource limits
        try:
            deployment = self.service_manager.k8s_client.read_namespaced_deployment(
                name=service_name,
                namespace="default"
            )
            
            deployment.spec.template.spec.containers[0].resources = client.V1ResourceRequirements(
                requests={
                    "cpu": f"{resources['cpu_cores']}",
                    "memory": f"{resources['ram_gb']}Gi"
                },
                limits={
                    "cpu": f"{resources['cpu_cores'] * 1.5}",
                    "memory": f"{resources['ram_gb'] * 1.2}Gi"
                }
            )
            
            await self.service_manager.k8s_client.replace_namespaced_deployment(
                name=service_name,
                namespace="default",
                body=deployment
            )
        except Exception as e:
            raise ServiceDeploymentError(f"Failed to update resource allocation: {str(e)}")

    async def store_metrics(self):
        async with DatabaseManager(self.config).get_connection() as session:
            metrics = NetworkMetrics(
                cpu_usage=self.resource_metrics['cpu_usage'],
                memory_usage=self.resource_metrics['memory_usage'],
                timestamp=datetime.utcnow()
            )
            session.add(metrics)
            await session.commit()

# Protocol-Specific Health Checks
class ProtocolHealthChecker:
    def __init__(self, config: NetworkConfig):
        self.config = config
        self.health_checks = {
            'WireGuard': self._check_wireguard,
            'OpenVPN': self._check_openvpn,
            'IPSec': self._check_ipsec
        }

    async def _check_wireguard(self, endpoint: str) -> Dict[str, Any]:
        try:
            # WireGuard-specific health checks
            result = await asyncio.create_subprocess_shell(
                f"wg show {endpoint} latest-handshakes",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                return {'status': 'unhealthy', 'error': stderr.decode()}
            
            handshake_time = int(stdout.decode().strip().split()[-1])
            return {
                'status': 'healthy' if handshake_time < 180 else 'degraded',
                'last_handshake': handshake_time
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    async def _check_openvpn(self, endpoint: str) -> Dict[str, Any]:
        try:
            # OpenVPN-specific health checks
            result = await asyncio.create_subprocess_shell(
                f"echo 'status' | nc -w 5 {endpoint} 7505",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                return {'status': 'unhealthy', 'error': stderr.decode()}
            
            status_output = stdout.decode()
            return {
                'status': 'healthy' if 'CONNECTED' in status_output else 'degraded',
                'connected_clients': status_output.count('CLIENT_LIST')
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    async def _check_ipsec(self, endpoint: str) -> Dict[str, Any]:
        try:
            # IPSec-specific health checks
            result = await asyncio.create_subprocess_shell(
                f"ipsec status",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                return {'status': 'unhealthy', 'error': stderr.decode()}
            
            status_output = stdout.decode()
            return {
                'status': 'healthy' if 'ESTABLISHED' in status_output else 'degraded',
                'active_tunnels': status_output.count('ESTABLISHED')
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    async def check_protocol(self, protocol: str, endpoint: str) -> Dict[str, Any]:
        if protocol not in self.health_checks:
            raise ValueError(f"Unsupported protocol: {protocol}")
        
        return await self.health_checks[protocol](endpoint)

# Main application setup with enhanced monitoring and resource management
def create_app() -> FastAPI:
    app = FastAPI(title="VPN Intelligence System")
    config = VPNIntelligenceConfig()
    
    # Initialize managers
    db_manager = DatabaseManager(config)
    resource_manager = ResourceManager()
    security_manager = SecurityManager(config.security)
    protocol_checker = ProtocolHealthChecker(config.network)
    
    # Setup middleware with rate limiting
    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        client_ip = request.client.host
        if not security_manager.check_rate_limit(client_ip, limit=100, window=60):
            raise HTTPException(status_code=429, detail="Too many requests")
        return await call_next(request)
    
    # Setup background tasks
    @app.on_event("startup")
    async def startup_event():
        asyncio.create_task(resource_manager.monitor_resources())
        asyncio.create_task(security_manager.rotate_certificates())
    
    # Setup shutdown
    @app.on_event("shutdown")
    async def shutdown_event():
        await db_manager.close_pool()
    
    return app

if __name__ == "__main__":
    app = create_app()
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        ssl_keyfile="/etc/vpn-intelligence/certs/key.pem",
        ssl_certfile="/etc/vpn-intelligence/certs/cert.pem",
        workers=4,
        loop="uvloop"
    )
