"""
Async Processing and WebSocket Streaming for Open-Interpreter Parlant Integration

Provides non-blocking validation with real-time streaming updates, background
processing, and concurrent operation management for high-throughput scenarios.

@author Async Processing Team
@since 1.0.0
@performance_targets Non-blocking validation, 1000+ concurrent streams, real-time updates
"""

import asyncio
import json
import logging
import time
import uuid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

import websockets
from websockets.server import WebSocketServerProtocol

from .performance_optimization import (
    ValidationRequest,
    ValidationRiskLevel,
    get_optimized_parlant_service,
)


class StreamingEventType(Enum):
    """Types of streaming events for real-time updates"""

    VALIDATION_STARTED = "validation_started"
    RISK_ASSESSMENT = "risk_assessment"
    CACHE_CHECK = "cache_check"
    CONVERSATIONAL_ANALYSIS = "conversational_analysis"
    VALIDATION_PROGRESS = "validation_progress"
    VALIDATION_COMPLETE = "validation_complete"
    VALIDATION_ERROR = "validation_error"
    BATCH_STARTED = "batch_started"
    BATCH_PROGRESS = "batch_progress"
    BATCH_COMPLETE = "batch_complete"
    PERFORMANCE_UPDATE = "performance_update"


@dataclass
class StreamingEvent:
    """Real-time streaming event with comprehensive metadata"""

    event_type: StreamingEventType
    stream_id: str
    operation_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    data: Dict[str, Any] = field(default_factory=dict)
    progress: float = 0.0  # 0.0 to 1.0
    estimated_completion: Optional[datetime] = None
    correlation_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert streaming event to dictionary for JSON serialization"""
        return {
            "event_type": self.event_type.value,
            "stream_id": self.stream_id,
            "operation_id": self.operation_id,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "progress": self.progress,
            "estimated_completion": (
                self.estimated_completion.isoformat()
                if self.estimated_completion
                else None
            ),
            "correlation_id": self.correlation_id,
        }


@dataclass
class ValidationStream:
    """Active validation stream with real-time updates"""

    stream_id: str
    operation_id: str
    websocket: Optional[WebSocketServerProtocol]
    created_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    events: deque = field(default_factory=lambda: deque(maxlen=100))
    status: str = "active"
    client_id: str = ""
    subscription_filters: Set[StreamingEventType] = field(default_factory=set)

    def is_expired(self, timeout_minutes: int = 30) -> bool:
        """Check if stream has expired due to inactivity"""
        return datetime.now() - self.last_activity > timedelta(minutes=timeout_minutes)

    def add_event(self, event: StreamingEvent) -> None:
        """Add event to stream history"""
        self.events.append(event)
        self.last_activity = datetime.now()


class WebSocketManager:
    """High-performance WebSocket connection manager with connection pooling"""

    def __init__(self):
        self.connections: Dict[str, WebSocketServerProtocol] = {}
        self.connection_metadata: Dict[str, Dict[str, Any]] = {}
        self.message_queues: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.heartbeat_interval = 30  # seconds
        self.logger = logging.getLogger(__name__)
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

        # Performance metrics
        self.metrics = {
            "total_connections": 0,
            "active_connections": 0,
            "messages_sent": 0,
            "messages_failed": 0,
            "connection_errors": 0,
            "bytes_sent": 0,
        }

    async def register_connection(
        self,
        client_id: str,
        websocket: WebSocketServerProtocol,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register new WebSocket connection with metadata"""
        async with self._lock:
            self.connections[client_id] = websocket
            self.connection_metadata[client_id] = {
                "connected_at": datetime.now(),
                "last_heartbeat": datetime.now(),
                "message_count": 0,
                "remote_address": websocket.remote_address,
                "user_agent": (
                    metadata.get("user_agent", "unknown") if metadata else "unknown"
                ),
                **(metadata or {}),
            }

            self.metrics["total_connections"] += 1
            self.metrics["active_connections"] = len(self.connections)

            # Start background tasks if first connection
            if len(self.connections) == 1:
                await self._start_background_tasks()

            self.logger.info(f"WebSocket connection registered: {client_id}")

    async def unregister_connection(self, client_id: str) -> None:
        """Unregister WebSocket connection and cleanup"""
        async with self._lock:
            if client_id in self.connections:
                try:
                    await self.connections[client_id].close()
                except Exception as e:
                    self.logger.warning(f"Error closing WebSocket for {client_id}: {e}")

                del self.connections[client_id]
                self.connection_metadata.pop(client_id, None)
                self.message_queues.pop(client_id, None)

                self.metrics["active_connections"] = len(self.connections)

                # Stop background tasks if no connections
                if not self.connections:
                    await self._stop_background_tasks()

                self.logger.info(f"WebSocket connection unregistered: {client_id}")

    async def send_to_client(
        self, client_id: str, event: StreamingEvent, retry_count: int = 3
    ) -> bool:
        """Send streaming event to specific client with retry logic"""
        if client_id not in self.connections:
            return False

        websocket = self.connections[client_id]
        message = json.dumps(event.to_dict())

        for attempt in range(retry_count):
            try:
                await websocket.send(message)

                # Update metrics
                self.metrics["messages_sent"] += 1
                self.metrics["bytes_sent"] += len(message.encode("utf-8"))
                self.connection_metadata[client_id]["message_count"] += 1

                return True

            except websockets.exceptions.ConnectionClosed:
                self.logger.warning(f"WebSocket connection closed for {client_id}")
                await self.unregister_connection(client_id)
                return False

            except Exception as e:
                self.logger.error(f"WebSocket send error (attempt {attempt + 1}): {e}")
                if attempt == retry_count - 1:
                    self.metrics["messages_failed"] += 1
                    return False

                await asyncio.sleep(0.1 * (attempt + 1))  # Exponential backoff

        return False

    async def broadcast_to_all(
        self, event: StreamingEvent, filter_func: Optional[Callable[[str], bool]] = None
    ) -> int:
        """Broadcast event to all connected clients with optional filtering"""
        successful_sends = 0

        client_ids = list(self.connections.keys())
        for client_id in client_ids:
            if filter_func and not filter_func(client_id):
                continue

            if await self.send_to_client(client_id, event):
                successful_sends += 1

        return successful_sends

    async def send_to_subscribers(
        self,
        event: StreamingEvent,
        event_type_filter: Optional[Set[StreamingEventType]] = None,
    ) -> int:
        """Send event to clients subscribed to specific event types"""
        if not event_type_filter:
            return await self.broadcast_to_all(event)

        def filter_func(client_id: str) -> bool:
            metadata = self.connection_metadata.get(client_id, {})
            subscriptions = metadata.get("subscriptions", set())
            return event.event_type in subscriptions

        return await self.broadcast_to_all(event, filter_func)

    async def queue_message_for_offline_client(
        self, client_id: str, event: StreamingEvent
    ) -> None:
        """Queue message for client that's currently offline"""
        self.message_queues[client_id].append(event.to_dict())

    async def flush_queued_messages(self, client_id: str) -> int:
        """Send all queued messages to reconnected client"""
        if client_id not in self.message_queues or not self.message_queues[client_id]:
            return 0

        sent_count = 0
        while self.message_queues[client_id]:
            message_data = self.message_queues[client_id].popleft()
            event = StreamingEvent(**message_data)

            if await self.send_to_client(client_id, event):
                sent_count += 1
            else:
                # Re-queue if send failed
                self.message_queues[client_id].appendleft(message_data)
                break

        return sent_count

    async def _start_background_tasks(self) -> None:
        """Start background maintenance tasks"""
        if not self._heartbeat_task or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        if not self._cleanup_task or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def _stop_background_tasks(self) -> None:
        """Stop background maintenance tasks"""
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def _heartbeat_loop(self) -> None:
        """Maintain WebSocket connections with periodic heartbeat"""
        while self.connections:
            try:
                current_time = datetime.now()
                heartbeat_event = StreamingEvent(
                    event_type=StreamingEventType.PERFORMANCE_UPDATE,
                    stream_id="heartbeat",
                    operation_id="system",
                    data={"type": "heartbeat", "timestamp": current_time.isoformat()},
                )

                # Send heartbeat to all connections
                client_ids = list(self.connections.keys())
                for client_id in client_ids:
                    await self.send_to_client(client_id, heartbeat_event)
                    self.connection_metadata[client_id]["last_heartbeat"] = current_time

                await asyncio.sleep(self.heartbeat_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Heartbeat error: {e}")
                await asyncio.sleep(5)

    async def _cleanup_loop(self) -> None:
        """Clean up stale connections and expired message queues"""
        while self.connections:
            try:
                current_time = datetime.now()
                stale_timeout = timedelta(minutes=5)

                # Find stale connections
                stale_clients = []
                for client_id, metadata in self.connection_metadata.items():
                    if current_time - metadata["last_heartbeat"] > stale_timeout:
                        stale_clients.append(client_id)

                # Remove stale connections
                for client_id in stale_clients:
                    self.logger.warning(
                        f"Removing stale WebSocket connection: {client_id}"
                    )
                    await self.unregister_connection(client_id)

                # Clean up old message queues
                old_queues = []
                for client_id, queue in self.message_queues.items():
                    if client_id not in self.connections and len(queue) == 0:
                        old_queues.append(client_id)

                for client_id in old_queues:
                    del self.message_queues[client_id]

                await asyncio.sleep(60)  # Run cleanup every minute

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Cleanup error: {e}")
                await asyncio.sleep(30)

    def get_connection_stats(self) -> Dict[str, Any]:
        """Get comprehensive WebSocket connection statistics"""
        return {
            "metrics": self.metrics,
            "active_connections": len(self.connections),
            "queued_messages": sum(
                len(queue) for queue in self.message_queues.values()
            ),
            "connection_details": {
                client_id: {
                    "connected_at": metadata["connected_at"].isoformat(),
                    "last_heartbeat": metadata["last_heartbeat"].isoformat(),
                    "message_count": metadata["message_count"],
                    "remote_address": str(metadata["remote_address"]),
                }
                for client_id, metadata in self.connection_metadata.items()
            },
        }


class StreamingValidationService:
    """Non-blocking validation service with real-time WebSocket streaming"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.websocket_manager = WebSocketManager()
        self.active_streams: Dict[str, ValidationStream] = {}
        self.stream_lock = asyncio.Lock()

        # Get optimized Parlant service
        self.parlant_service = get_optimized_parlant_service()

        # Background processing
        self.background_executor = ThreadPoolExecutor(max_workers=20)
        self.deferred_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)

        # Performance tracking
        self.streaming_metrics = {
            "streams_created": 0,
            "streams_completed": 0,
            "streams_failed": 0,
            "events_streamed": 0,
            "background_validations": 0,
            "deferred_validations": 0,
        }

        # Start background processing
        asyncio.create_task(self._process_deferred_validations())

    async def start_streaming_validation(
        self,
        request: ValidationRequest,
        client_id: str,
        websocket: Optional[WebSocketServerProtocol] = None,
    ) -> str:
        """
        Start non-blocking validation with real-time streaming updates

        Returns stream_id immediately while validation continues in background
        """
        stream_id = f"stream_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"

        # Create validation stream
        stream = ValidationStream(
            stream_id=stream_id,
            operation_id=request.operation_id,
            websocket=websocket,
            client_id=client_id,
        )

        async with self.stream_lock:
            self.active_streams[stream_id] = stream

        # Send immediate response with stream info
        start_event = StreamingEvent(
            event_type=StreamingEventType.VALIDATION_STARTED,
            stream_id=stream_id,
            operation_id=request.operation_id,
            data={
                "operation": request.operation,
                "risk_level": request.risk_level.value,
                "estimated_duration_ms": self._estimate_validation_time(request),
                "cache_enabled": request.cache_enabled,
            },
            progress=0.1,
        )

        await self._emit_streaming_event(client_id, start_event)

        # Start background validation
        asyncio.create_task(self._process_streaming_validation(request, stream))

        self.streaming_metrics["streams_created"] += 1
        return stream_id

    async def start_batch_streaming_validation(
        self,
        requests: List[ValidationRequest],
        client_id: str,
        websocket: Optional[WebSocketServerProtocol] = None,
    ) -> str:
        """Start batch validation with streaming progress updates"""
        batch_stream_id = (
            f"batch_stream_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
        )

        # Send batch started event
        batch_start_event = StreamingEvent(
            event_type=StreamingEventType.BATCH_STARTED,
            stream_id=batch_stream_id,
            operation_id="batch_operation",
            data={
                "batch_size": len(requests),
                "estimated_duration_ms": sum(
                    self._estimate_validation_time(req) for req in requests
                ),
                "operations": [req.operation for req in requests],
            },
            progress=0.0,
        )

        await self._emit_streaming_event(client_id, batch_start_event)

        # Start background batch processing
        asyncio.create_task(
            self._process_batch_streaming(requests, batch_stream_id, client_id)
        )

        return batch_stream_id

    async def defer_validation(
        self, request: ValidationRequest, priority: int = 5
    ) -> str:
        """Queue validation for background processing during low-traffic periods"""
        deferred_id = f"deferred_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"

        # Add to deferred processing queue
        await self.deferred_queue.put(
            {
                "id": deferred_id,
                "request": request,
                "priority": priority,
                "queued_at": datetime.now(),
            }
        )

        self.streaming_metrics["deferred_validations"] += 1
        return deferred_id

    async def _process_streaming_validation(
        self, request: ValidationRequest, stream: ValidationStream
    ) -> None:
        """Process validation with real-time streaming updates"""
        try:
            client_id = stream.client_id

            # Stream risk assessment progress
            risk_event = StreamingEvent(
                event_type=StreamingEventType.RISK_ASSESSMENT,
                stream_id=stream.stream_id,
                operation_id=request.operation_id,
                data={"risk_level": request.risk_level.value},
                progress=0.2,
            )
            await self._emit_streaming_event(client_id, risk_event)

            # Stream cache check progress
            cache_event = StreamingEvent(
                event_type=StreamingEventType.CACHE_CHECK,
                stream_id=stream.stream_id,
                operation_id=request.operation_id,
                data={"cache_enabled": request.cache_enabled},
                progress=0.3,
            )
            await self._emit_streaming_event(client_id, cache_event)

            # Stream conversational analysis for high-risk operations
            if request.risk_level in [
                ValidationRiskLevel.HIGH,
                ValidationRiskLevel.CRITICAL,
            ]:
                analysis_event = StreamingEvent(
                    event_type=StreamingEventType.CONVERSATIONAL_ANALYSIS,
                    stream_id=stream.stream_id,
                    operation_id=request.operation_id,
                    data={"analyzing": True},
                    progress=0.6,
                )
                await self._emit_streaming_event(client_id, analysis_event)

            # Perform actual validation
            validation_result = await self.parlant_service.validate_operation_optimized(
                request
            )

            # Stream completion
            complete_event = StreamingEvent(
                event_type=StreamingEventType.VALIDATION_COMPLETE,
                stream_id=stream.stream_id,
                operation_id=request.operation_id,
                data={
                    "approved": validation_result.approved,
                    "confidence": validation_result.confidence,
                    "reasoning": validation_result.reasoning,
                    "processing_time_ms": validation_result.processing_time_ms,
                    "cache_hit": validation_result.cache_hit,
                },
                progress=1.0,
            )
            await self._emit_streaming_event(client_id, complete_event)

            # Update stream status
            stream.status = "completed"
            self.streaming_metrics["streams_completed"] += 1

        except Exception as e:
            # Stream error
            error_event = StreamingEvent(
                event_type=StreamingEventType.VALIDATION_ERROR,
                stream_id=stream.stream_id,
                operation_id=request.operation_id,
                data={"error": str(e), "error_type": type(e).__name__},
                progress=0.0,
            )
            await self._emit_streaming_event(stream.client_id, error_event)

            stream.status = "failed"
            self.streaming_metrics["streams_failed"] += 1
            self.logger.error(f"Streaming validation error: {e}")

    async def _process_batch_streaming(
        self, requests: List[ValidationRequest], batch_stream_id: str, client_id: str
    ) -> None:
        """Process batch validation with streaming progress updates"""
        try:
            total_requests = len(requests)
            completed = 0

            # Process batch with the optimized service
            results = await self.parlant_service.validate_batch_optimized(requests)

            # Stream progress for each completed validation
            for i, result in enumerate(results):
                completed += 1
                progress = completed / total_requests

                progress_event = StreamingEvent(
                    event_type=StreamingEventType.BATCH_PROGRESS,
                    stream_id=batch_stream_id,
                    operation_id=requests[i].operation_id,
                    data={
                        "completed": completed,
                        "total": total_requests,
                        "current_result": {
                            "approved": result.approved,
                            "confidence": result.confidence,
                            "operation_id": result.operation_id,
                        },
                    },
                    progress=progress,
                )
                await self._emit_streaming_event(client_id, progress_event)

            # Stream batch completion
            batch_complete_event = StreamingEvent(
                event_type=StreamingEventType.BATCH_COMPLETE,
                stream_id=batch_stream_id,
                operation_id="batch_operation",
                data={
                    "total_processed": len(results),
                    "approved_count": sum(1 for r in results if r.approved),
                    "average_confidence": sum(r.confidence for r in results)
                    / len(results),
                    "total_processing_time_ms": sum(
                        r.processing_time_ms for r in results
                    ),
                },
                progress=1.0,
            )
            await self._emit_streaming_event(client_id, batch_complete_event)

        except Exception as e:
            error_event = StreamingEvent(
                event_type=StreamingEventType.VALIDATION_ERROR,
                stream_id=batch_stream_id,
                operation_id="batch_operation",
                data={"error": str(e), "batch_size": len(requests)},
                progress=0.0,
            )
            await self._emit_streaming_event(client_id, error_event)
            self.logger.error(f"Batch streaming error: {e}")

    async def _process_deferred_validations(self) -> None:
        """Background worker for processing deferred validations"""
        while True:
            try:
                # Get deferred validation from queue
                deferred_item = await self.deferred_queue.get()

                request = deferred_item["request"]

                # Process validation in background
                result = await self.parlant_service.validate_operation_optimized(
                    request
                )

                self.streaming_metrics["background_validations"] += 1

                # Mark task as done
                self.deferred_queue.task_done()

            except Exception as e:
                self.logger.error(f"Deferred validation error: {e}")
                await asyncio.sleep(1)

    async def _emit_streaming_event(
        self, client_id: str, event: StreamingEvent
    ) -> None:
        """Emit streaming event to client with error handling"""
        try:
            await self.websocket_manager.send_to_client(client_id, event)
            self.streaming_metrics["events_streamed"] += 1

            # Add event to stream history if stream exists
            stream = self.active_streams.get(event.stream_id)
            if stream:
                stream.add_event(event)

        except Exception as e:
            self.logger.error(f"Error emitting streaming event: {e}")

    def _estimate_validation_time(self, request: ValidationRequest) -> int:
        """Estimate validation time in milliseconds based on risk level"""
        time_estimates = {
            ValidationRiskLevel.LOW: 50,  # 50ms for low risk (cached/auto-approved)
            ValidationRiskLevel.MEDIUM: 200,  # 200ms for medium risk
            ValidationRiskLevel.HIGH: 500,  # 500ms for high risk
            ValidationRiskLevel.CRITICAL: 1000,  # 1000ms for critical risk
        }
        return time_estimates.get(request.risk_level, 200)

    async def cleanup_expired_streams(self) -> int:
        """Clean up expired validation streams"""
        async with self.stream_lock:
            expired_streams = []
            for stream_id, stream in self.active_streams.items():
                if stream.is_expired():
                    expired_streams.append(stream_id)

            for stream_id in expired_streams:
                del self.active_streams[stream_id]

            return len(expired_streams)

    def get_streaming_stats(self) -> Dict[str, Any]:
        """Get comprehensive streaming performance statistics"""
        return {
            "streaming_metrics": self.streaming_metrics,
            "active_streams": len(self.active_streams),
            "deferred_queue_size": self.deferred_queue.qsize(),
            "websocket_stats": self.websocket_manager.get_connection_stats(),
            "stream_details": {
                stream_id: {
                    "operation_id": stream.operation_id,
                    "status": stream.status,
                    "created_at": stream.created_at.isoformat(),
                    "last_activity": stream.last_activity.isoformat(),
                    "event_count": len(stream.events),
                }
                for stream_id, stream in self.active_streams.items()
            },
        }


# WebSocket Server for Real-Time Validation Streaming
class ValidationWebSocketServer:
    """WebSocket server for real-time validation streaming"""

    def __init__(self, host: str = "localhost", port: int = 8765):
        self.host = host
        self.port = port
        self.streaming_service = StreamingValidationService()
        self.logger = logging.getLogger(__name__)
        self.server: Optional[websockets.WebSocketServer] = None

    async def start_server(self) -> None:
        """Start WebSocket server for streaming validation"""
        self.server = await websockets.serve(
            self.handle_websocket_connection,
            self.host,
            self.port,
            ping_interval=20,
            ping_timeout=10,
            close_timeout=10,
        )

        self.logger.info(
            f"Validation WebSocket server started on ws://{self.host}:{self.port}"
        )

    async def stop_server(self) -> None:
        """Stop WebSocket server gracefully"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.logger.info("Validation WebSocket server stopped")

    async def handle_websocket_connection(
        self, websocket: WebSocketServerProtocol, path: str
    ) -> None:
        """Handle individual WebSocket connections"""
        client_id = f"client_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"

        try:
            # Register connection
            await self.streaming_service.websocket_manager.register_connection(
                client_id, websocket
            )

            self.logger.info(f"WebSocket client connected: {client_id}")

            # Handle messages
            async for message in websocket:
                await self._handle_websocket_message(client_id, websocket, message)

        except websockets.exceptions.ConnectionClosed:
            self.logger.info(f"WebSocket client disconnected: {client_id}")
        except Exception as e:
            self.logger.error(f"WebSocket error for {client_id}: {e}")
        finally:
            # Unregister connection
            await self.streaming_service.websocket_manager.unregister_connection(
                client_id
            )

    async def _handle_websocket_message(
        self, client_id: str, websocket: WebSocketServerProtocol, message: str
    ) -> None:
        """Handle incoming WebSocket messages"""
        try:
            data = json.loads(message)
            message_type = data.get("type")

            if message_type == "start_validation":
                # Start streaming validation
                request_data = data.get("request", {})
                request = ValidationRequest(
                    operation_id=f"ws_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}",
                    operation=request_data.get("operation", "unknown"),
                    context=request_data.get("context", {}),
                    user_intent=request_data.get("user_intent", ""),
                    risk_level=ValidationRiskLevel(
                        request_data.get("risk_level", "medium")
                    ),
                )

                stream_id = await self.streaming_service.start_streaming_validation(
                    request, client_id, websocket
                )

                # Send confirmation
                await websocket.send(
                    json.dumps(
                        {
                            "type": "stream_started",
                            "stream_id": stream_id,
                            "client_id": client_id,
                        }
                    )
                )

            elif message_type == "start_batch_validation":
                # Start batch streaming validation
                requests_data = data.get("requests", [])
                requests = []

                for req_data in requests_data:
                    request = ValidationRequest(
                        operation_id=f"batch_ws_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}",
                        operation=req_data.get("operation", "unknown"),
                        context=req_data.get("context", {}),
                        user_intent=req_data.get("user_intent", ""),
                        risk_level=ValidationRiskLevel(
                            req_data.get("risk_level", "medium")
                        ),
                    )
                    requests.append(request)

                batch_stream_id = (
                    await self.streaming_service.start_batch_streaming_validation(
                        requests, client_id, websocket
                    )
                )

                # Send confirmation
                await websocket.send(
                    json.dumps(
                        {
                            "type": "batch_stream_started",
                            "stream_id": batch_stream_id,
                            "batch_size": len(requests),
                            "client_id": client_id,
                        }
                    )
                )

            elif message_type == "get_stats":
                # Send performance statistics
                stats = self.streaming_service.get_streaming_stats()
                await websocket.send(
                    json.dumps({"type": "stats_response", "stats": stats})
                )

        except Exception as e:
            self.logger.error(f"Error handling WebSocket message from {client_id}: {e}")
            await websocket.send(json.dumps({"type": "error", "message": str(e)}))


# Global streaming service instance
_streaming_service: Optional[StreamingValidationService] = None


def get_streaming_service() -> StreamingValidationService:
    """Get global streaming service instance"""
    global _streaming_service
    if _streaming_service is None:
        _streaming_service = StreamingValidationService()
    return _streaming_service
