# app/api/v1/endpoints/protocols.py

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Dict, Optional
import asyncio
import os

from app.core.database import get_db
from app.core.logger import logger, log_audit
from app.models import User, UserProtocol, ProtocolSettings
from app.schemas.protocol import (
    ProtocolConfig, ProtocolStatus, ProtocolStats,
    PortConfig, UserConfig
)
from app.api.deps import get_current_active_user
from app.core.config import settings
from app.utils.helpers import (
    execute_command,
    check_port_available,
    find_available_port
)

router = APIRouter()

@router.get("/", response_model=List[ProtocolConfig])
async def list_protocols(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all available protocols and their configurations"""
    protocols = db.query(ProtocolSettings).all()
    return protocols

@router.get("/{protocol}", response_model=ProtocolConfig)
async def get_protocol(
    protocol: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get protocol configuration"""
    protocol_config = db.query(ProtocolSettings).filter(
        ProtocolSettings.protocol == protocol
    ).first()
    
    if not protocol_config:
        raise HTTPException(status_code=404, detail="Protocol not found")
    
    return protocol_config

@router.put("/{protocol}", response_model=ProtocolConfig)
async def update_protocol(
    protocol: str,
    config: ProtocolConfig,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update protocol configuration"""
    protocol_config = db.query(ProtocolSettings).filter(
        ProtocolSettings.protocol == protocol
    ).first()
    
    if not protocol_config:
        protocol_config = ProtocolSettings(protocol=protocol)
        db.add(protocol_config)

    protocol_config.port = config.port
    protocol_config.config = config.config
    protocol_config.enabled = config.enabled
    
    db.commit()
    db.refresh(protocol_config)

    log_audit(
        "protocol_updated",
        current_user.id,
        f"Updated configuration for {protocol}"
    )
    return protocol_config

@router.post("/{protocol}/restart")
async def restart_protocol(
    protocol: str,
    current_user: User = Depends(get_current_active_user)
):
    """Restart protocol service"""
    script_path = os.path.join(settings.MODULES_DIR, f"{protocol}-script.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Protocol script not found")

    result = await execute_command([script_path, "restart"])
    if not result['success']:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to restart {protocol}: {result['stderr']}"
        )

    log_audit(
        "protocol_restarted",
        current_user.id,
        f"Restarted {protocol} service"
    )
    return {"message": f"{protocol} restarted successfully"}

@router.get("/{protocol}/status", response_model=ProtocolStatus)
async def get_protocol_status(
    protocol: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get protocol service status"""
    script_path = os.path.join(settings.MODULES_DIR, f"{protocol}-script.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Protocol script not found")

    result = await execute_command([script_path, "status"])
    if not result['success']:
        return {
            "status": "stopped",
            "running": False,
            "error": result['stderr']
        }

    return {
        "status": "running",
        "running": True,
        "pid": int(result['stdout'].strip()) if result['stdout'].strip().isdigit() else None
    }

@router.get("/{protocol}/stats", response_model=ProtocolStats)
async def get_protocol_stats(
    protocol: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get protocol statistics"""
    script_path = os.path.join(settings.MODULES_DIR, f"{protocol}-script.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Protocol script not found")

    result = await execute_command([script_path, "stats"])
    if not result['success']:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get stats for {protocol}: {result['stderr']}"
        )

    try:
        stats = json.loads(result['stdout'])
        return stats
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="Invalid stats format returned by protocol script"
        )

@router.post("/{protocol}/port", response_model=PortConfig)
async def update_protocol_port(
    protocol: str,
    port_config: PortConfig,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update protocol port"""
    if not await check_port_available(port_config.port):
        raise HTTPException(
            status_code=400,
            detail=f"Port {port_config.port} is already in use"
        )

    protocol_config = db.query(ProtocolSettings).filter(
        ProtocolSettings.protocol == protocol
    ).first()
    
    if not protocol_config:
        raise HTTPException(status_code=404, detail="Protocol not found")

    script_path = os.path.join(settings.MODULES_DIR, f"{protocol}-script.py")
    result = await execute_command([
        script_path,
        "update-port",
        str(port_config.port)
    ])

    if not result['success']:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update port: {result['stderr']}"
        )

    protocol_config.port = port_config.port
    db.commit()

    log_audit(
        "port_updated",
        current_user.id,
        f"Updated {protocol} port to {port_config.port}"
    )
    return port_config

@router.post("/{protocol}/optimize-ports")
async def optimize_protocol_ports(
    protocol: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Find and set optimal ports for protocol"""
    new_port = await find_available_port()
    if not new_port:
        raise HTTPException(
            status_code=500,
            detail="No available ports found"
        )

    protocol_config = db.query(ProtocolSettings).filter(
        ProtocolSettings.protocol == protocol
    ).first()
    
    if not protocol_config:
        raise HTTPException(status_code=404, detail="Protocol not found")

    script_path = os.path.join(settings.MODULES_DIR, f"{protocol}-script.py")
    result = await execute_command([
        script_path,
        "update-port",
        str(new_port)
    ])

    if not result['success']:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update port: {result['stderr']}"
        )

    protocol_config.port = new_port
    db.commit()

    log_audit(
        "port_optimized",
        current_user.id,
        f"Optimized {protocol} port to {new_port}"
    )
    return {"port": new_port}

@router.post("/{protocol}/users/{user_id}/config", response_model=UserConfig)
async def generate_user_config(
    protocol: str,
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Generate user configuration for protocol"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    protocol_config = db.query(UserProtocol).filter(
        UserProtocol.user_id == user_id,
        UserProtocol.protocol == protocol
    ).first()

    if not protocol_config:
        raise HTTPException(
            status_code=404,
            detail="Protocol not configured for user"
        )

    script_path = os.path.join(settings.MODULES_DIR, f"{protocol}-script.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Protocol script not found")

    result = await execute_command([
        script_path,
        "generate-config",
        "--username", user.username,
        "--config", json.dumps(protocol_config.config)
    ])

    if not result['success']:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate config: {result['stderr']}"
        )

    try:
        config = json.loads(result['stdout'])
        return config
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="Invalid config format returned by protocol script"
        )

@router.get("/{protocol}/users", response_model=List[UserConfig])
async def list_protocol_users(
    protocol: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all users configured for protocol"""
    users = db.query(UserProtocol).filter(
        UserProtocol.protocol == protocol
    ).all()
    return users

@router.post("/{protocol}/validate-config")
async def validate_protocol_config(
    protocol: str,
    config: Dict,
    current_user: User = Depends(get_current_active_user)
):
    """Validate protocol configuration"""
    script_path = os.path.join(settings.MODULES_DIR, f"{protocol}-script.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Protocol script not found")

    result = await execute_command([
        script_path,
        "validate-config",
        json.dumps(config)
    ])

    if not result['success']:
        return {
            "valid": False,
            "errors": result['stderr'].split('\n')
        }

    return {
        "valid": True
    }

@router.post("/{protocol}/backup")
async def backup_protocol(
    protocol: str,
    current_user: User = Depends(get_current_active_user)
):
    """Backup protocol configuration and data"""
    script_path = os.path.join(settings.MODULES_DIR, f"{protocol}-script.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Protocol script not found")

    backup_dir = os.path.join(settings.BACKUP_DIR, protocol)
    os.makedirs(backup_dir, exist_ok=True)

    backup_file = os.path.join(
        backup_dir,
        f"{protocol}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.tar.gz"
    )

    result = await execute_command([
        script_path,
        "backup",
        "--output", backup_file
    ])

    if not result['success']:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create backup: {result['stderr']}"
        )

    log_audit(
        "protocol_backup",
        current_user.id,
        f"Created backup for {protocol}"
    )
    return {
        "message": f"Backup created successfully",
        "file": backup_file
    }

@router.post("/{protocol}/restore")
async def restore_protocol(
    protocol: str,
    background_tasks: BackgroundTasks,
    backup_file: str,
    current_user: User = Depends(get_current_active_user)
):
    """Restore protocol from backup"""
    if not os.path.exists(backup_file):
        raise HTTPException(status_code=404, detail="Backup file not found")

    script_path = os.path.join(settings.MODULES_DIR, f"{protocol}-script.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Protocol script not found")

    # Add restore task to background tasks
    async def restore_task():
        result = await execute_command([
            script_path,
            "restore",
            "--input", backup_file
        ])
        
        if not result['success']:
            logger.error(f"Failed to restore {protocol}: {result['stderr']}")
            return

        log_audit(
            "protocol_restored",
            current_user.id,
            f"Restored {protocol} from backup"
        )

    background_tasks.add_task(restore_task)

    return {
        "message": "Restore process started in background"
    }

@router.post("/{protocol}/test-connection")
async def test_protocol_connection(
    protocol: str,
    config: Dict,
    current_user: User = Depends(get_current_active_user)
):
    """Test protocol connection with given configuration"""
    script_path = os.path.join(settings.MODULES_DIR, f"{protocol}-script.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Protocol script not found")

    result = await execute_command([
        script_path,
        "test-connection",
        json.dumps(config)
    ])

    return {
        "success": result['success'],
        "message": result['stdout'] if result['success'] else result['stderr']
    }

@router.post("/{protocol}/optimize")
async def optimize_protocol(
    protocol: str,
    current_user: User = Depends(get_current_active_user)
):
    """Optimize protocol settings for better performance"""
    script_path = os.path.join(settings.MODULES_DIR, f"{protocol}-script.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Protocol script not found")

    result = await execute_command([
        script_path,
        "optimize"
    ])

    if not result['success']:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to optimize {protocol}: {result['stderr']}"
        )

    try:
        optimized_config = json.loads(result['stdout'])
        return optimized_config
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="Invalid optimization result returned by protocol script"
        )

@router.get("/{protocol}/logs")
async def get_protocol_logs(
    protocol: str,
    lines: int = 100,
    current_user: User = Depends(get_current_active_user)
):
    """Get protocol logs"""
    log_file = os.path.join(settings.LOG_DIR, f"{protocol}.log")
    if not os.path.exists(log_file):
        return {
            "lines": []
        }

    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()[-lines:]
            return {
                "lines": lines
            }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to read logs: {str(e)}"
        )
