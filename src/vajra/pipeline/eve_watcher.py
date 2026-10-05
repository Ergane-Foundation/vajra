#!/usr/bin/env python3
"""
Simple eve.json watcher - broadcasts ALL events to WebSocket clients
No filtering, no processing - just raw eve.json data streaming
"""

import asyncio
import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("eve_watcher")

# Create FastAPI app
app = FastAPI(title="Eve.json Live Stream", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Client connected. Total: {len(self.active_connections)}")
    
    async def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"Client disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast to all connected clients"""
        if not self.active_connections:
            return
        
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Broadcast error: {e}")
                disconnected.append(connection)
        
        for conn in disconnected:
            await self.disconnect(conn)

manager = ConnectionManager()

# Eve.json file watcher
EVE_JSON_PATH = Path("logs/eve.json")
eve_position = 0

async def watch_eve_json():
    """Watch eve.json and broadcast ALL events to WebSocket clients"""
    global eve_position
    
    logger.info(f"Watching {EVE_JSON_PATH} for events...")
    
    while True:
        try:
            if not EVE_JSON_PATH.exists():
                await asyncio.sleep(1)
                continue
            
            current_size = EVE_JSON_PATH.stat().st_size
            
            # File rotated/truncated
            if current_size < eve_position:
                eve_position = 0
                logger.info("Eve.json file rotated")
            
            # New data available
            if current_size > eve_position:
                with open(EVE_JSON_PATH, 'r') as f:
                    f.seek(eve_position)
                    
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            event = json.loads(line)
                            
                            # Broadcast raw event to all clients
                            await manager.broadcast(event)
                            
                        except json.JSONDecodeError as e:
                            logger.warning(f"Invalid JSON: {e}")
                            continue
                    
                    eve_position = f.tell()
            
            await asyncio.sleep(0.1)  # Check every 100ms
            
        except Exception as e:
            logger.error(f"Eve watcher error: {e}")
            await asyncio.sleep(1)

@app.on_event("startup")
async def startup():
    """Start eve.json watcher on startup"""
    logger.info("Starting Eve.json watcher...")
    asyncio.create_task(watch_eve_json())
    logger.info("Eve watcher started")

@app.get("/health")
async def health():
    return {"status": "healthy", "watching": str(EVE_JSON_PATH)}

@app.get("/stats")
async def stats():
    return {
        "active_connections": len(manager.active_connections),
        "file_position": eve_position,
        "file_exists": EVE_JSON_PATH.exists()
    }

@app.websocket("/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint - streams raw eve.json events"""
    await manager.connect(websocket)
    
    try:
        # Send connection confirmation
        await websocket.send_json({
            "type": "connection",
            "status": "connected",
            "message": "Live eve.json stream",
            "timestamp": datetime.now().isoformat()
        })
        
        # Keep connection alive
        while True:
            try:
                # Receive ping/pong
                data = await websocket.receive_json()
                if data.get('type') == 'ping':
                    await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "heartbeat"})
    
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await manager.disconnect(websocket)

if __name__ == "__main__":
    host = os.environ.get("VAJRA_API_HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=8000, log_level="info")
