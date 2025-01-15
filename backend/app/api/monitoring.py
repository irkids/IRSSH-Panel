# app/api/monitoring.py

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import asyncio
import psutil
import json

from app.core.database import get_db
from app.core.logger import logger
from app.models import User, Connection, BandwidthUsage
from app.schemas.monitoring import (
    SystemMetrics,
    ResourceUsage,
    NetworkStats,
    ProcessInfo,
    AlertConfig
)
from app.api.deps import get_current_active_user
from app.utils.helpers import get_system_stats, get_process_info

router = APIRouter()

# Real-time monitoring connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                await self.disconnect(connection)

manager = ConnectionManager()

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Get real-time metrics
            metrics = await get_system_stats()
            await websocket.send_text(json.dumps(metrics))
            await asyncio.sleep(1)  # Update every second
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@router.get("/metrics", response_model=SystemMetrics)
async def get_current_metrics(
    current_user: User = Depends(get_current_active_user)
):
    """Get current system metrics"""
    return await get_system_stats()

@router.get("/resources/{resource_type}", response_model=ResourceUsage)
async def get_resource_usage(
    resource_type: str,
    period: str = "1h",
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get historical resource usage"""
    # Calculate time range
    period_map = {
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "24h": timedelta(days=1),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30)
    }
    
    if period not in period_map:
        raise HTTPException(
            status_code=400,
            detail="Invalid period. Must be one of: 1h, 6h, 24h, 7d, 30d"
        )

    start_time = datetime.utcnow() - period_map[period]

    # Query resource usage from database
    metrics = db.query(SystemMetrics).filter(
        SystemMetrics.timestamp >= start_time
    ).order_by(SystemMetrics.timestamp.asc()).all()

    data = []
    for metric in metrics:
        if resource_type == "cpu":
            value = metric.cpu_usage
        elif resource_type == "memory":
            value = metric.memory_usage
        elif resource_type == "disk":
            value = metric.disk_usage
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid resource type. Must be one of: cpu, memory, disk"
            )
        
        data.append({
            "timestamp": metric.timestamp,
            "value": value
        })

    return {
        "resource_type": resource_type,
        "period": period,
        "start_time": start_time,
        "end_time": datetime.utcnow(),
        "data": data
    }

@router.get("/network", response_model=NetworkStats)
async def get_network_stats(
    period: str = "1h",
    protocol: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get network traffic statistics"""
    period_map = {
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "24h": timedelta(days=1),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30)
    }
    
    start_time = datetime.utcnow() - period_map[period]

    # Query bandwidth usage
    query = db.query(BandwidthUsage).filter(
        BandwidthUsage.timestamp >= start_time
    )
    
    if protocol:
        query = query.filter(BandwidthUsage.protocol == protocol)

    usage = query.order_by(BandwidthUsage.timestamp.asc()).all()

    data = []
    total_sent = 0
    total_received = 0

    for record in usage:
        total_sent += record.bytes_sent
        total_received += record.bytes_received
        data.append({
            "timestamp": record.timestamp,
            "bytes_sent": record.bytes_sent,
            "bytes_received": record.bytes_received,
            "protocol": record.protocol
        })

    return {
        "period": period,
        "start_time": start_time,
        "end_time": datetime.utcnow(),
        "total_sent": total_sent,
        "total_received": total_received,
        "data": data
    }

@router.get("/processes", response_model=List[ProcessInfo])
async def get_process_info(
    name: Optional[str] = None,
    current_user: User = Depends(get_current_active_user)
):
    """Get information about running processes"""
    return await get_process_info(name if name else '')

@router.get("/alerts/config", response_model=AlertConfig)
async def get_alert_config(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get system alert configuration"""
    config = db.query(SystemSettings).filter(
        SystemSettings.key == 'alert_config'
    ).first()

    if not config:
        # Return default config
        return {
            "thresholds": {
                "cpu": 80,
                "memory": 80,
                "disk": 90,
                "bandwidth": 1000  # Mbps
            },
            "notifications": {
                "email": False,
                "telegram": False
            },
            "check_interval": 60  # seconds
        }

    return config.value

@router.post("/alerts/config")
async def update_alert_config(
    config: AlertConfig,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update system alert configuration"""
    setting = db.query(SystemSettings).filter(
        SystemSettings.key == 'alert_config'
    ).first()

    if setting:
        setting.value = config.dict()
    else:
        setting = SystemSettings(
            key='alert_config',
            value=config.dict()
        )
        db.add(setting)

    db.commit()
    return {"message": "Alert configuration updated"}

@router.get("/alerts/test")
async def test_alerts(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Test alert notifications"""
    try:
        # Get alert config
        config = db.query(SystemSettings).filter(
            SystemSettings.key == 'alert_config'
        ).first()

        if not config:
            raise HTTPException(
                status_code=400,
                detail="Alert configuration not found"
            )

        # Test email notification
        if config.value['notifications']['email']:
            # Implement email sending
            pass

        # Test Telegram notification
        if config.value['notifications']['telegram']:
            from app.utils.helpers import send_telegram_message
            await send_telegram_message(
                "🔔 This is a test alert from IRSSH Panel"
            )

        return {"message": "Test alerts sent successfully"}

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send test alerts: {str(e)}"
        )

@router.websocket("/alerts/ws")
async def alert_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time alerts"""
    await manager.connect(websocket)
    try:
        while True:
            # Get system metrics
            metrics = await get_system_stats()

            # Get alert config
            async with Session() as db:
                config = db.query(SystemSettings).filter(
                    SystemSettings.key == 'alert_config'
                ).first()

                if config:
                    thresholds = config.value['thresholds']
                    alerts = []

                    # Check CPU usage
                    if metrics['cpu']['percent'] > thresholds['cpu']:
                        alerts.append({
                            'type': 'cpu',
                            'level': 'warning',
                            'message': f"CPU usage is {metrics['cpu']['percent']}%"
                        })

                    # Check memory usage
                    if metrics['memory']['percent'] > thresholds['memory']:
                        alerts.append({
                            'type': 'memory',
                            'level': 'warning',
                            'message': f"Memory usage is {metrics['memory']['percent']}%"
                        })

                    # Check disk usage
                    if metrics['disk']['percent'] > thresholds['disk']:
                        alerts.append({
                            'type': 'disk',
                            'level': 'warning',
                            'message': f"Disk usage is {metrics['disk']['percent']}%"
                        })

                    if alerts:
                        await websocket.send_text(json.dumps({
                            'timestamp': datetime.utcnow().isoformat(),
                            'alerts': alerts
                        }))

            await asyncio.sleep(config.value['check_interval'] if config else 60)

    except WebSocketDisconnect:
        manager.disconnect(websocket)

@router.get("/geo-distribution")
async def get_geo_distribution(
    period: str = "24h",
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get geographical distribution of connections"""
    period_map = {
        "24h": timedelta(days=1),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30)
    }
    
    start_time = datetime.utcnow() - period_map[period]

    connections = db.query(Connection).filter(
        Connection.connected_at >= start_time
    ).all()

    distribution = {}
    for conn in connections:
        if conn.location:
            country = conn.location.get('country', 'Unknown')
            if country not in distribution:
                distribution[country] = {
                    'connections': 0,
                    'bytes_sent': 0,
                    'bytes_received': 0
                }
            distribution[country]['connections'] += 1
            distribution[country]['bytes_sent'] += conn.bytes_sent
            distribution[country]['bytes_received'] += conn.bytes_received

    return {
        'period': period,
        'start_time': start_time,
        'total_connections': len(connections),
        'distribution': distribution
    }

@router.get("/health")
async def health_check():
    """System health check endpoint"""
    try:
        # Check database connection
        async with Session() as db:
            await db.execute("SELECT 1")

        # Check disk space
        disk = psutil.disk_usage('/')
        if disk.percent > 95:
            return {
                'status': 'warning',
                'message': f'Low disk space: {disk.percent}% used'
            }

        # Check memory
        memory = psutil.virtual_memory()
        if memory.percent > 95:
            return {
                'status': 'warning',
                'message': f'Low memory: {memory.percent}% used'
            }

        return {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat()
        }

    except Exception as e:
        return {
            'status': 'unhealthy',
            'message': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }
