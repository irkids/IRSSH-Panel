#!/usr/bin/env python3
import os
os.environ.setdefault("SSH_DB_HOST", "localhost")
os.environ.setdefault("SSH_DB_PORT", "5432")
os.environ.setdefault("SSH_DB_NAME", "ssh_manager")
os.environ.setdefault("SSH_DB_USER", "ssh_user")
os.environ.setdefault("SSH_DB_PASSWORD", "SCRAM-SHA-256$4096:/ReBlqoM6ktVBRWRL9AA+g==$7zRf07anW9X6anq9mu+tZmzqgdre7AI6tO2YAWRsqy0=:MYxeFEe4xR/zmTeMa9yory8tLBiBKLv+YEcnAKZDMhg=")

import sys
try:
    from dotenv import load_dotenv
except ImportError:
    import pip
    pip.main(['install', 'python-dotenv'])
    from dotenv import load_dotenv

load_dotenv()

import asyncio
import logging
import logging.handlers
import subprocess
import prometheus_client as prom
import socket
import ssl
import psycopg2
import json
import yaml
import time
import structlog
import websockets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from psycopg2.pool import SimpleConnectionPool
from prometheus_client import Counter, Gauge, Histogram

# Prometheus metrics
ACTIVE_CONNECTIONS = Gauge('ssh_active_connections', 'Number of active connections', ['protocol'])
LATENCY_HISTOGRAM = Histogram('ssh_connection_latency_seconds', 'SSH connection latency')
THROUGHPUT_GAUGE = Gauge('ssh_connection_throughput_bytes', 'SSH connection throughput')
BUFFER_USAGE_GAUGE = Gauge('ssh_buffer_usage_bytes', 'SSH buffer usage')
ERROR_COUNTER = Counter('ssh_errors_total', 'Number of SSH errors', ['type'])

class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

@dataclass
class OptimizedConfig:
    # Database settings
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "ssh_manager"
    db_user: str = "ssh_user"
    db_password: str = ""
    min_pool_size: int = 2
    max_pool_size: int = 5

    # Base server settings
    host: str = "0.0.0.0"
    port: int = 22
    backlog: int = 100
    max_connections: int = 50
    log_dir: Path = Path("/var/log/enhanced_ssh")
    config_dir: Path = Path("/etc/enhanced_ssh")
    cert_dir: Path = Path("/etc/enhanced_ssh/certs")
    metrics_dir: Path = Path("/var/lib/enhanced_ssh/metrics")

    # Security settings
    ssl_enabled: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    waf_enabled: bool = False
    waf_rules: Dict = field(default_factory=dict)

    # Resource optimization
    worker_processes: int = 1
    worker_connections: int = 100
    keepalive_timeout: int = 65
    client_max_body_size: str = "1m"

    # Cache settings
    cache_enabled: bool = True
    cache_max_size: int = 10  # MB
    cache_expiration: int = 3600  # 1 hour

    @classmethod
    def from_env(cls):
        """Create configuration from environment variables"""
        return cls(
            db_host=os.getenv("SSH_DB_HOST", "localhost"),
            db_port=int(os.getenv("SSH_DB_PORT", "5432")),
            db_name=os.getenv("SSH_DB_NAME", "ssh_manager"),
            db_user=os.getenv("SSH_DB_USER", "ssh_user"),
            db_password=os.getenv("SSH_DB_PASSWORD", ""),
        )

class DatabasePool:
    """Singleton database connection pool"""
    _instance = None
    _pool = None

    def __new__(cls, config: OptimizedConfig):
        if cls._instance is None:
            cls._instance = super(DatabasePool, cls).__new__(cls)
            cls._instance._config = config
            cls._instance._setup_pool()
        return cls._instance

    def _setup_pool(self):
        """Setup database connection pool"""
        if self._pool is None:
            self._pool = SimpleConnectionPool(
                self._config.min_pool_size,
                self._config.max_pool_size,
                host=self._config.db_host,
                port=self._config.db_port,
                dbname=self._config.db_name,
                user=self._config.db_user,
                password=self._config.db_password
            )

    @contextmanager
    def get_connection(self):
        """Get database connection from pool"""
        conn = self._pool.getconn()
        try:
            yield conn
        finally:
            self._pool.putconn(conn)

class ResourceManager:
    """Manages system resources and optimization"""
    def __init__(self, config: OptimizedConfig):
        self.config = config
        self.logger = structlog.get_logger()
        self.metrics = {
            'cpu_usage': Gauge('ssh_cpu_usage_percent', 'CPU usage percentage'),
            'memory_usage': Gauge('ssh_memory_usage_percent', 'Memory usage percentage'),
            'disk_usage': Gauge('ssh_disk_usage_percent', 'Disk usage percentage'),
            'system_load': Gauge('ssh_system_load', 'System load average')
        }
        self.current_stats = {}

    async def monitor_resources(self):
        """Monitor system resources"""
        while True:
            try:
                await self._collect_metrics()
                await self._optimize_resources()
                await asyncio.sleep(30)
            except Exception as e:
                self.logger.error(f"Resource monitoring error: {e}")

    async def _collect_metrics(self):
        """Collect system metrics"""
        try:
            import psutil
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.metrics['cpu_usage'].set(cpu_percent)
            self.current_stats['cpu'] = cpu_percent

            # Memory usage
            memory = psutil.virtual_memory()
            self.metrics['memory_usage'].set(memory.percent)
            self.current_stats['memory'] = memory.percent

            # Disk usage
            disk = psutil.disk_usage('/')
            self.metrics['disk_usage'].set(disk.percent)
            self.current_stats['disk'] = disk.percent

            # System load
            load = psutil.getloadavg()[0]
            self.metrics['system_load'].set(load)
            self.current_stats['load'] = load

        except Exception as e:
            self.logger.error(f"Error collecting metrics: {e}")

    async def _optimize_resources(self):
        """Optimize system resources based on current usage"""
        try:
            if self.current_stats.get('memory', 0) > 80:
                await self._handle_high_memory()
            if self.current_stats.get('cpu', 0) > 80:
                await self._handle_high_cpu()
        except Exception as e:
            self.logger.error(f"Resource optimization error: {e}")

class SSHBaseProtocol(ABC):
    """Base class for all SSH protocols"""
    def __init__(self, config: OptimizedConfig):
        self.config = config
        self.logger = structlog.get_logger()
        self.active_connections = set()
        self._setup_ssl()

    def _setup_ssl(self):
        """Setup SSL context if enabled"""
        if self.config.ssl_enabled and self.config.ssl_cert_path and self.config.ssl_key_path:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(
                self.config.ssl_cert_path, 
                self.config.ssl_key_path
            )
        else:
            self.ssl_context = None

    @abstractmethod
    async def start(self):
        """Start the protocol server"""
        pass

    @abstractmethod
    async def stop(self):
        """Stop the protocol server"""
        pass

class SSHDirectProtocol(SSHBaseProtocol):
    """Direct SSH protocol implementation"""
    
    async def authenticate_user(self, reader, writer):
        """Authenticate users when connecting"""
        writer.write(b"Enter username: ")
        await writer.drain()
        username = (await reader.read(100)).decode().strip()

        writer.write(b"Enter password: ")
        await writer.drain()
        password = (await reader.read(100)).decode().strip()

        auth = SSHAuthenticator()
        if not auth.authenticate(username, password):
            writer.write(b"Authentication failed.\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return False

        writer.write(b"Authentication successful!\n")
        await writer.drain()
        return True

    async def start(self):
        server = await asyncio.start_server(
            self.handle_connection,
            self.config.host,
            self.config.port,
            backlog=self.config.backlog
        )

        self.logger.info(f"SSH-DIRECT started on {self.config.host}:{self.config.port}")
        return server

async def handle_connection(self, reader, writer):
    """Handle SSH connection"""
    try:
        peer = writer.get_extra_info('peername')
        self.logger.info(f"New connection from {peer}")

        if not await self.authenticate_user(reader, writer):
            return

        while True:
            data = await reader.read(8192)
            if not data:
                break
                
            # Process SSH data
            response = await self._process_ssh_data(data)
            if response:
                writer.write(response)
                await writer.drain()
                
    except Exception as e:
        self.logger.error(f"Connection error: {e}")
        ERROR_COUNTER.labels(type='connection').inc()
    finally:
        self.active_connections.remove(writer)
        writer.close()
        await writer.wait_closed()

class SSHTLSProtocol(SSHBaseProtocol):
    """SSH over TLS protocol implementation"""
    async def start(self):
        if not self.ssl_context:
            raise ValueError("SSL context required for SSH-TLS")
            
        server = await asyncio.start_server(
            self.handle_connection,
            self.config.host,
            self.config.port,
            ssl=self.ssl_context,
            backlog=self.config.backlog
        )
        self.logger.info(f"SSH-TLS started on {self.config.host}:{self.config.port}")
        return server

class SSHDropbearProtocol(SSHBaseProtocol):
    """Dropbear SSH protocol implementation"""
    def __init__(self, config: OptimizedConfig):
        super().__init__(config)
        self.dropbear_process = None

    async def start(self):
        try:
            cmd = [
                'dropbear',
                '-F',  # Don't fork
                '-E',  # Log to stderr
                '-p', f"{self.config.host}:{self.config.port}"
            ]
            
            if self.ssl_context:
                cmd.extend([
                    '-r', self.config.ssl_key_path,
                    '-c', self.config.ssl_cert_path
                ])
                
            self.dropbear_process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            self.logger.info(f"SSH-DROPBEAR started on {self.config.host}:{self.config.port}")
            
        except Exception as e:
            self.logger.error(f"Failed to start Dropbear: {e}")
            raise

class SSHWebSocketProtocol(SSHBaseProtocol):
    """WebSocket SSH protocol implementation"""
    def __init__(self, config: OptimizedConfig):
        super().__init__(config)
        self.ws_server = None

    async def start(self):
        self.ws_server = await websockets.serve(
            self.handle_websocket,
            self.config.host,
            self.config.port,
            ssl=self.ssl_context,
            max_size=65536,
            ping_interval=30,
            ping_timeout=10
        )
        self.logger.info(f"SSH-WEBSOCKET started on {self.config.host}:{self.config.port}")

    async def handle_websocket(self, websocket, path):
        """Handle WebSocket connection"""
        try:
            self.active_connections.add(websocket)
            async for message in websocket:
                response = await self._process_ssh_message(message)
                await websocket.send(response)
        except websockets.exceptions.ConnectionClosed:
            self.logger.info("WebSocket connection closed")
        except Exception as e:
            self.logger.error(f"WebSocket error: {e}")
            ERROR_COUNTER.labels(type='websocket').inc()
        finally:
            self.active_connections.remove(websocket)

class EnhancedSSHServer:
    """Main SSH server class"""
    def __init__(self, config_path: str = "/etc/enhanced_ssh/config.yaml"):
        self.logger = self._setup_logging()
        self.config = self._load_config(config_path)

        self.db_pool = DatabasePool(self.config)
        self.resource_manager = ResourceManager(self.config)
        self.protocols = {}
        
    def _load_config(self, config_path: str) -> OptimizedConfig:
        """Load server configuration"""
        try:
            with open(config_path) as f:
                config_dict = yaml.safe_load(f)
            return OptimizedConfig(**config_dict)
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            return OptimizedConfig()

    def _setup_logging(self) -> structlog.BoundLogger:
        """Setup structured logging"""
        structlog.configure(
            processors=[
                structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
                structlog.processors.JSONRenderer()
            ],
            wrapper_class=structlog.BoundLogger,
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory()
        )
        return structlog.get_logger()

    async def start(self):
        """Start SSH server"""
        try:
            # Initialize protocols
            protocol_classes = {
                'direct': SSHDirectProtocol,
                'tls': SSHTLSProtocol,
                'dropbear': SSHDropbearProtocol,
                'dropbear-tls': SSHDropbearProtocol,
                'websocket': SSHWebSocketProtocol,
                'websocket-tls': SSHWebSocketProtocol
            }

            # Start enabled protocols
            for protocol_name, protocol_class in protocol_classes.items():
                if getattr(self.config, f'{protocol_name}_enabled', False):
                    protocol = protocol_class(self.config)
                    await protocol.start()
                    self.protocols[protocol_name] = protocol

            # Start resource monitoring
            asyncio.create_task(self.resource_manager.monitor_resources())

            self.logger.info("Enhanced SSH Server started successfully")
            
            # Keep server running
            while True:
                await asyncio.sleep(3600)
                
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            raise

    async def stop(self):
        """Stop SSH server"""
        try:
            for protocol in self.protocols.values():
                await protocol.stop()
            self.logger.info("Enhanced SSH Server stopped")
        except Exception as e:
            self.logger.error(f"Error stopping server: {e}")
            raise

def signal_handler():
    """Setup signal handlers."""
    import signal
    def handle_sigterm(signum, frame):
        logging.info("Received SIGTERM signal")
        asyncio.get_event_loop().stop()
    def handle_sighup(signum, frame):
        logging.info("Received SIGHUP signal")
    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGHUP, handle_sighup)

async def main():
    """Main entry point."""
    server = EnhancedSSHServer()
    prom.start_http_server(9100)
    await server.start()
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    # Create /etc/enhanced_ssh directory and config.yaml file if they don't exist.
    config_dir = "/etc/enhanced_ssh"
    config_file = os.path.join(config_dir, "config.yaml")
    os.makedirs(config_dir, exist_ok=True)
    if not os.path.exists(config_file):
        with open(config_file, "w") as f:
            f.write("db_host: localhost\n")
            f.write("db_port: 5432\n")
            f.write("db_name: ssh_manager\n")
            f.write("db_user: ssh_user\n")
            f.write("db_password: MySecureP@ssw0rd\n")
    
    # Create log directory if it doesn't exist.
    os.makedirs('/var/log/enhanced_ssh', exist_ok=True)

    # Configure logging.
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('/var/log/enhanced_ssh/server.log')
        ]
    )

    # Setup signal handlers.
    signal_handler()

    # Create event loop and run the main program.
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        logging.info("Received shutdown signal")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        pending = asyncio.all_tasks(loop)
        loop.run_until_complete(asyncio.gather(*pending))
        loop.close()
