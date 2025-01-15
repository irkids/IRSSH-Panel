# app/utils/helpers.py

import os
import json
import socket
import hashlib
import subprocess
from typing import Dict, List, Optional, Union
from datetime import datetime, timedelta
import psutil
import aiofiles
from app.core.logger import logger
from app.core.config import settings

async def get_system_stats() -> Dict:
    """Get system resource statistics"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()

        return {
            'cpu': {
                'percent': cpu_percent,
                'cores': psutil.cpu_count()
            },
            'memory': {
                'total': memory.total,
                'used': memory.used,
                'free': memory.free,
                'percent': memory.percent
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': disk.percent
            },
            'network': {
                'bytes_sent': network.bytes_sent,
                'bytes_recv': network.bytes_recv,
                'packets_sent': network.packets_sent,
                'packets_recv': network.packets_recv
            }
        }
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return {}

async def check_port_available(port: int) -> bool:
    """Check if a port is available"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result != 0
    except Exception as e:
        logger.error(f"Error checking port {port}: {e}")
        return False

async def find_available_port(start_port: int = 1024, end_port: int = 65535) -> Optional[int]:
    """Find an available port in the given range"""
    for port in range(start_port, end_port + 1):
        if await check_port_available(port):
            return port
    return None

async def execute_command(command: Union[str, List[str]], shell: bool = False) -> Dict:
    """Execute a shell command async"""
    try:
        if isinstance(command, list) and shell:
            command = ' '.join(command)

        process = await asyncio.create_subprocess_shell(
            command if shell else ' '.join(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        return {
            'success': process.returncode == 0,
            'stdout': stdout.decode(),
            'stderr': stderr.decode(),
            'code': process.returncode
        }
    except Exception as e:
        logger.error(f"Error executing command: {e}")
        return {
            'success': False,
            'stdout': '',
            'stderr': str(e),
            'code': -1
        }

def format_bytes(bytes: int) -> str:
    """Format bytes to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024
    return f"{bytes:.2f} PB"

def calculate_checksum(file_path: str) -> str:
    """Calculate SHA256 checksum of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

async def save_json(data: Dict, file_path: str) -> bool:
    """Save dictionary to JSON file"""
    try:
        async with aiofiles.open(file_path, 'w') as f:
            await f.write(json.dumps(data, indent=2))
        return True
    except Exception as e:
        logger.error(f"Error saving JSON file: {e}")
        return False

async def load_json(file_path: str) -> Optional[Dict]:
    """Load JSON file to dictionary"""
    try:
        async with aiofiles.open(file_path, 'r') as f:
            content = await f.read()
        return json.loads(content)
    except Exception as e:
        logger.error(f"Error loading JSON file: {e}")
        return None

def get_geolocation(ip: str) -> Dict:
    """Get geolocation info for IP address"""
    try:
        import geoip2.database
        reader = geoip2.database.Reader(os.path.join(settings.MODULES_DIR, 'GeoLite2-City.mmdb'))
        response = reader.city(ip)
        return {
            'country': response.country.name,
            'city': response.city.name,
            'latitude': response.location.latitude,
            'longitude': response.location.longitude,
            'timezone': response.location.time_zone
        }
    except Exception as e:
        logger.error(f"Error getting geolocation for IP {ip}: {e}")
        return {}

def generate_password(length: int = 12) -> str:
    """Generate secure random password"""
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + "@#$%&*"
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                                and any(c in "@#$%&*" for c in password)):
            return password

def generate_uuid() -> str:
    """Generate UUID for user identification"""
    return str(uuid.uuid4())

async def send_telegram_message(message: str) -> bool:
    """Send message via Telegram bot"""
    if not (settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID):
        return False

    try:
        url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json={
                'chat_id': settings.TELEGRAM_CHAT_ID,
                'text': message,
                'parse_mode': 'HTML'
            }) as response:
                return response.status == 200
    except Exception as e:
        logger.error(f"Error sending Telegram message: {e}")
        return False

async def create_backup_archive(paths: List[str], backup_name: str) -> Optional[str]:
    """Create a backup archive of specified paths"""
    try:
        backup_path = os.path.join(settings.BACKUP_DIR, f"{backup_name}.tar.gz")
        command = f"tar -czf {backup_path} {' '.join(paths)}"
        result = await execute_command(command, shell=True)
        if result['success']:
            return backup_path
        return None
    except Exception as e:
        logger.error(f"Error creating backup archive: {e}")
        return None

async def extract_backup_archive(archive_path: str, extract_path: str) -> bool:
    """Extract backup archive to specified path"""
    try:
        command = f"tar -xzf {archive_path} -C {extract_path}"
        result = await execute_command(command, shell=True)
        return result['success']
    except Exception as e:
        logger.error(f"Error extracting backup archive: {e}")
        return False

def validate_ip_range(ip_range: str) -> bool:
    """Validate IP range format (CIDR notation)"""
    try:
        import ipaddress
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False

async def get_process_info(name: str) -> List[Dict]:
    """Get information about running processes by name"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent', 'create_time']):
        try:
            if name.lower() in proc.info['name'].lower():
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'username': proc.info['username'],
                    'memory_percent': proc.info['memory_percent'],
                    'cpu_percent': proc.info['cpu_percent'],
                    'create_time': datetime.fromtimestamp(proc.info['create_time']).isoformat()
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

async def clean_old_files(directory: str, days: int) -> int:
    """Clean files older than specified days"""
    cleaned = 0
    now = datetime.now()
    try:
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                if (now - mtime).days > days:
                    os.remove(filepath)
                    cleaned += 1
        return cleaned
    except Exception as e:
        logger.error(f"Error cleaning old files: {e}")
        return -1

def parse_config_template(template: str, variables: Dict) -> str:
    """Parse configuration template with variables"""
    try:
        from string import Template
        return Template(template).safe_substitute(variables)
    except Exception as e:
        logger.error(f"Error parsing config template: {e}")
        return template

async def verify_ssl_cert(cert_path: str) -> Dict:
    """Verify SSL certificate and get details"""
    try:
        import OpenSSL
        with open(cert_path, 'rb') as f:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
        
        return {
            'subject': dict(cert.get_subject().get_components()),
            'issuer': dict(cert.get_issuer().get_components()),
            'not_before': datetime.strptime(cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ').isoformat(),
            'not_after': datetime.strptime(cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ').isoformat(),
            'serial_number': cert.get_serial_number(),
            'valid': datetime.now() < datetime.strptime(cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
        }
    except Exception as e:
        logger.error(f"Error verifying SSL certificate: {e}")
        return {}

def normalize_protocol_name(protocol: str) -> str:
    """Normalize protocol name for consistency"""
    protocol_map = {
        'ss': 'shadowsocks',
        'wg': 'wireguard',
        'ike': 'ikev2',
        'l2': 'l2tp',
        'any': 'cisco'
    }
    protocol = protocol.lower().strip()
    return protocol_map.get(protocol, protocol)

async def test_port_connectivity(host: str, port: int, timeout: int = 5) -> Dict:
    """Test TCP port connectivity"""
    try:
        start_time = datetime.now()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        end_time = datetime.now()
        writer.close()
        await writer.wait_closed()
        
        return {
            'success': True,
            'latency_ms': (end_time - start_time).total_seconds() * 1000,
            'error': None
        }
    except Exception as e:
        return {
            'success': False,
            'latency_ms': None,
            'error': str(e)
        }

def calculate_traffic_stats(bytes_data: List[int], interval: int = 60) -> Dict:
    """Calculate traffic statistics from byte counts"""
    if not bytes_data or len(bytes_data) < 2:
        return {
            'current': 0,
            'average': 0,
            'peak': 0,
            'total': sum(bytes_data)
        }
    
    deltas = [bytes_data[i] - bytes_data[i-1] for i in range(1, len(bytes_data))]
    bits_per_second = [(d * 8) / interval for d in deltas]
    
    return {
        'current': bits_per_second[-1],
        'average': sum(bits_per_second) / len(bits_per_second),
        'peak': max(bits_per_second),
        'total': sum(bytes_data)
    }
