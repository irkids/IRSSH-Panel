# app/api/v1/endpoints/settings.py

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Dict, List
import os
import json
from datetime import datetime

from app.core.database import get_db
from app.core.logger import logger, log_audit
from app.models import SystemSettings, Backup
from app.schemas.settings import (
    SystemConfig,
    BackupConfig,
    BackupInfo,
    RestoreConfig
)
from app.api.deps import get_current_active_user
from app.core.config import settings
from app.utils.helpers import (
    execute_command,
    calculate_checksum,
    save_json,
    load_json,
    clean_old_files
)

router = APIRouter()

@router.get("/system", response_model=SystemConfig)
async def get_system_settings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get all system settings"""
    settings = {}
    for setting in db.query(SystemSettings).all():
        settings[setting.key] = setting.value
    return settings

@router.post("/system", response_model=SystemConfig)
async def update_system_settings(
    config: Dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update system settings"""
    for key, value in config.items():
        setting = db.query(SystemSettings).filter(
            SystemSettings.key == key
        ).first()
        
        if setting:
            setting.value = value
        else:
            setting = SystemSettings(key=key, value=value)
            db.add(setting)
    
    db.commit()

    log_audit(
        "settings_updated",
        current_user.id,
        f"Updated system settings"
    )
    return config

@router.post("/backup", response_model=BackupInfo)
async def create_backup(
    config: BackupConfig,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create system backup"""
    backup_dir = settings.BACKUP_DIR
    os.makedirs(backup_dir, exist_ok=True)

    # Create backup entry
    backup = Backup(
        filename=f"backup-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.tar.gz",
        components=config.components,
        status="creating",
        notes=config.notes
    )
    db.add(backup)
    db.commit()

    # Background backup task
    async def backup_task():
        try:
            backup_path = os.path.join(backup_dir, backup.filename)
            paths_to_backup = []

            # Add component paths
            if 'database' in config.components:
                paths_to_backup.append(settings.DB_BACKUP_PATH)
            if 'config' in config.components:
                paths_to_backup.append(settings.CONFIG_DIR)
            if 'certificates' in config.components:
                paths_to_backup.append(settings.CERTS_DIR)
            if 'logs' in config.components:
                paths_to_backup.append(settings.LOG_DIR)

            # Create archive
            result = await execute_command([
                'tar', '-czf', backup_path, *paths_to_backup
            ])

            if not result['success']:
                raise Exception(f"Backup creation failed: {result['stderr']}")

            # Update backup info
            backup.size = os.path.getsize(backup_path)
            backup.checksum = calculate_checksum(backup_path)
            backup.status = "completed"
            
            if config.telegram and settings.TELEGRAM_BOT_TOKEN:
                # Send to Telegram
                from app.utils.helpers import send_telegram_message
                await send_telegram_message(
                    f"New backup created: {backup.filename}\n"
                    f"Size: {backup.size}\n"
                    f"Components: {', '.join(config.components)}"
                )

            db.commit()

            # Clean old backups
            if config.cleanup:
                await clean_old_files(backup_dir, settings.BACKUP_RETENTION_DAYS)

        except Exception as e:
            logger.error(f"Backup failed: {str(e)}")
            backup.status = "failed"
            db.commit()

    background_tasks.add_task(backup_task)

    return {
        "id": backup.id,
        "filename": backup.filename,
        "status": "creating",
        "message": "Backup creation started"
    }

@router.get("/backups", response_model=List[BackupInfo])
async def list_backups(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all backups"""
    backups = db.query(Backup).order_by(Backup.created_at.desc()).all()
    return backups

@router.get("/backups/{backup_id}", response_model=BackupInfo)
async def get_backup_info(
    backup_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get backup information"""
    backup = db.query(Backup).filter(Backup.id == backup_id).first()
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")
    return backup

@router.delete("/backups/{backup_id}")
async def delete_backup(
    backup_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete backup"""
    backup = db.query(Backup).filter(Backup.id == backup_id).first()
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")

    # Delete file
    backup_path = os.path.join(settings.BACKUP_DIR, backup.filename)
    if os.path.exists(backup_path):
        os.remove(backup_path)

    # Delete record
    db.delete(backup)
    db.commit()

    log_audit(
        "backup_deleted",
        current_user.id,
        f"Deleted backup {backup.filename}"
    )
    return {"message": "Backup deleted successfully"}

@router.post("/restore", response_model=Dict)
async def restore_system(
    config: RestoreConfig,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Restore system from backup"""
    backup = db.query(Backup).filter(Backup.id == config.backup_id).first()
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")

    backup_path = os.path.join(settings.BACKUP_DIR, backup.filename)
    if not os.path.exists(backup_path):
        raise HTTPException(status_code=404, detail="Backup file not found")

    # Verify checksum
    if calculate_checksum(backup_path) != backup.checksum:
        raise HTTPException(
            status_code=400,
            detail="Backup file checksum verification failed"
        )

    async def restore_task():
        try:
            # Create temp directory
            temp_dir = f"/tmp/restore-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
            os.makedirs(temp_dir, exist_ok=True)

            # Extract backup
            result = await execute_command([
                'tar', '-xzf', backup_path, '-C', temp_dir
            ])

            if not result['success']:
                raise Exception(f"Backup extraction failed: {result['stderr']}")

            # Restore components
            if 'database' in config.components:
                # Stop services
                await execute_command(['systemctl', 'stop', 'irssh-panel'])
                
                # Restore database
                result = await execute_command([
                    'pg_restore',
                    '-h', settings.DB_HOST,
                    '-U', settings.DB_USER,
                    '-d', settings.DB_NAME,
                    '-c',
                    os.path.join(temp_dir, 'database.dump')
                ])
                
                # Start services
                await execute_command(['systemctl', 'start', 'irssh-panel'])

            if 'config' in config.components:
                # Copy config files
                await execute_command([
                    'cp', '-r',
                    os.path.join(temp_dir, 'config', '*'),
                    settings.CONFIG_DIR
                ])

            if 'certificates' in config.components:
                # Copy certificates
                await execute_command([
                    'cp', '-r',
                    os.path.join(temp_dir, 'certs', '*'),
                    settings.CERTS_DIR
                ])

            # Clean up
            await execute_command(['rm', '-rf', temp_dir])

            log_audit(
                "system_restored",
                current_user.id,
                f"Restored system from backup {backup.filename}"
            )

        except Exception as e:
            logger.error(f"Restore failed: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Restore failed: {str(e)}"
            )

    background_tasks.add_task(restore_task)

    return {
        "message": "System restore started",
        "backup_id": backup.id,
        "components": config.components
    }

@router.post("/system/optimize")
async def optimize_system(
    current_user: User = Depends(get_current_active_user)
):
    """Optimize system settings and performance"""
    try:
        # Optimize database
        await execute_command(['vacuumdb', '-z', '-d', settings.DB_NAME])

        # Clean logs
        await clean_old_files(settings.LOG_DIR, 30)  # Keep 30 days of logs

        # Optimize system parameters
        await execute_command(['sysctl', '-p'])

        log_audit(
            "system_optimized",
            current_user.id,
            "Optimized system settings"
        )
        return {"message": "System optimization completed"}

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Optimization failed: {str(e)}"
        )
