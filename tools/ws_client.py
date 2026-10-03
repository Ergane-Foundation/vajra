import asyncio
import websockets
import json

async def listen():
    uri = "ws://localhost:8000/ws/logs"  # Removed trailing slash
    print(f"Connecting to {uri}...")

    try:
        async with websockets.connect(uri) as websocket:
            print("[OK] Connected!")

            while True:
                # Wait for message
                message = await websocket.recv()
                data = json.loads(message)

                # Handle different message types
                msg_type = data.get('type')
                
                if msg_type in ['connection', 'heartbeat', 'pong']:
                    print(f"System message: {msg_type}")
                    continue
                
                # Security event received
                print(f"Alert: [{data.get('threat_level', 'unknown').upper()}] {data.get('signature', data.get('description', 'Unknown'))}")
                print(f"   Source: {data.get('src_ip', 'N/A')} -> {data.get('dst_ip', 'N/A')}:{data.get('dst_port', 'N/A')}")
                print(f"   Type: {data.get('event_type', 'unknown')} | Component: {data.get('source_component', 'N/A')}")
                print()

    except websockets.exceptions.ConnectionClosed:
        print("[FAIL] Connection closed by server")
    except Exception as e:
        print(f"[WARN] Error: {e}")

if __name__ == "__main__":
    asyncio.run(listen())