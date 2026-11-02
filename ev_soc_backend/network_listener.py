import json
import time
from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict

class NetworkOCPPManager:
    def __init__(self, digital_twin):
        self.digital_twin = digital_twin
        self.active_connections: Dict[str, WebSocket] = {}

    async def handle_connection(self, websocket: WebSocket, station_id: str):
        await websocket.accept(subprotocol="ocpp1.6")
        self.active_connections[station_id] = websocket
        
        # Ensure station state exists in digital twin
        if station_id not in self.digital_twin.states:
            self.digital_twin.initialize_station(station_id)

        try:
            while True:
                start_time = time.time()
                data = await websocket.receive_text()
                latency_ms = (time.time() - start_time) * 1000

                # Process the frame and update telemetry
                await self.process_ocpp_frame(station_id, data, latency_ms)

        except WebSocketDisconnect:
            del self.active_connections[station_id]

    async def process_ocpp_frame(self, station_id: str, raw_payload: str, latency_ms: float):
        state = self.digital_twin.states[station_id]
        state.telemetry.network_latency_ms = round(latency_ms, 2)
        
        try:
            message = json.loads(raw_payload)
            # OCPP Call message format: [MessageTypeId, UniqueId, Action, Payload]
            if isinstance(message, list) and len(message) >= 4:
                action = message[2]
                payload = message[3]

                # Check for unauthorized / rogue actions
                if action == "StopTransaction":
                    id_tag = payload.get("idTag", "")
                    if id_tag.startswith("UNAUTHORIZED") or id_tag == "INVALID":
                        state.telemetry.failed_auth_attempts += 1
                        state.active_attack_type = "UNAUTHORIZED_HIJACK_ATTEMPT"
                
                elif action == "Authorize":
                    if payload.get("idTag") == "BAD_TAG":
                        state.telemetry.failed_auth_attempts += 1

        except json.JSONDecodeError:
            # Malformed JSON payload detected on wire
            state.telemetry.packet_loss_pct += 5.0
            state.active_attack_type = "MALFORMED_PROTOCOL_PAYLOAD"

        # Trigger risk engine check on live updated state
        self.digital_twin.evaluate_risk(station_id)