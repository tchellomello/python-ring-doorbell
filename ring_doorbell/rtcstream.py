"""Python Ring Doorbell RTC Stream handler."""
import asyncio
import contextlib
import functools
import logging
import uuid
from json import dumps as json_dumps
from json import loads as json_loads

from websockets.client import connect

from ring_doorbell.const import (
    RTC_STREAMING_TICKET_ENDPOINT,
    RTC_STREAMING_WEB_SOCKET_ENDPOINT,
)
from ring_doorbell.exceptions import RingError

_LOGGER = logging.getLogger(__name__)

ICE_CANDIDATE_COLLECTION_SECONDS = 1


class RingWebRtcStream:
    def __init__(self, ring, device_api_d):
        self._ring = ring
        self.device_api_id = device_api_d
        self.sdp: str = None
        self.websocket = None
        self.do_ping = False
        self.ping_task = None
        self.read_task = None
        self.ice_candidates = {0: [], 1: [], 2: [], 3: []}
        self.collect_ice_candidates = False

    async def generate(self, sdp_offer):
        """Generate the RTC stream"""
        self.collect_ice_candidates = True
        self.do_ping = True

        try:
            loop = asyncio.get_running_loop()
            _LOGGER.debug("Generating stream with sdp offer: %s", sdp_offer)
            req = await loop.run_in_executor(
                None,
                functools.partial(
                    self._ring.query,
                    RTC_STREAMING_TICKET_ENDPOINT,
                    method="POST",
                    base_uri="https://app.ring.com",
                ),
            )
            ticket = req.json()["ticket"]

            _LOGGER.debug(
                "Received RTC streaming ticket from endpoint, creating websocket"
            )
            ws_uri = f"wss://api.prod.signalling.ring.devices.a2z.com:443/ws?api_version=4.0&auth_type=ring_solutions&client_id=ring_site-{uuid.uuid4()}&token={ticket}"
            ws_uri = RTC_STREAMING_WEB_SOCKET_ENDPOINT.format(uuid.uuid4(), ticket)

            self.websocket = await connect(
                ws_uri, user_agent_header="android:com.ringapp"
            )

            self.dialog_id = str(uuid.uuid4())
            msg = {
                "method": "live_view",
                "dialog_id": self.dialog_id,
                "body": {
                    "doorbot_id": self.device_api_id,
                    "stream_options": {"audio_enabled": True, "video_enabled": True},
                    "sdp": sdp_offer,
                    "type": "offer",
                },
            }
            _LOGGER.debug(
                "Connected to RTC streaming websocket, sending live_view message: %s",
                msg,
            )
            await self.websocket.send(json_dumps(msg))

            message = await self.websocket.recv()
            # Should be session created message
            await self.handle_message(message)

            message2 = await self.websocket.recv()
            # Should be sdp answer message
            await self.handle_message(message2)

            activate_msg = self.get_session_message("activate_session", {})
            _LOGGER.debug("Sending activate_session message: %s", activate_msg)
            await self.websocket.send(json_dumps(activate_msg))

            options_msg = self.get_session_message(
                "stream_options", {"video_enabled": True, "audio_enabled": True}
            )
            _LOGGER.debug("Sending stream_options message: %s", options_msg)
            await self.websocket.send(json_dumps(options_msg))

            _LOGGER.debug("Starting ping and reader tasks")
            self.ping_task = asyncio.create_task(self.pinger())
            self.read_task = asyncio.create_task(self.reader())

            _LOGGER.debug(
                "Waiting %s seconds for ice candidates",
                ICE_CANDIDATE_COLLECTION_SECONDS,
            )
            await asyncio.sleep(ICE_CANDIDATE_COLLECTION_SECONDS)
            self.insert_ice_candidates()
        except Exception as ex:
            raise RingError("Error generating RTC stream", ex) from ex

        _LOGGER.debug("Returning SDP answer: %s", self.sdp)
        return self.sdp

    async def close(self):
        _LOGGER.debug("Closing the RTC Stream")
        self.do_ping = False
        if self.ping_task and not self.ping_task.done():
            self.ping_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.ping_task
            self.ping_task = None
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
        if self.read_task and not self.read_task.done():
            await self.read_task
            self.read_task = None

    def get_session_message(self, method, body):
        message = {
            "method": method,
            "dialog_id": self.dialog_id,
            "body": {
                **body,
                "doorbot_id": self.device_api_id,
                "session_id": self.session_id,
            },
        }
        return message

    async def reader(self):
        async for message in self.websocket:
            await self.handle_message(message)

    async def pinger(self):
        while self.do_ping:
            await asyncio.sleep(3)
            ping = self.get_session_message("ping", {})
            await self.websocket.send(json_dumps(ping))

    def handle_ice_message(self, ice_candidate, multi_line_index):
        _LOGGER.debug(
            "Ice candidate received, multi_line_index: %s candidate: %s",
            multi_line_index,
            ice_candidate,
        )
        if self.collect_ice_candidates:
            self.ice_candidates[int(multi_line_index)].append(ice_candidate)

    def insert_ice_candidates(self):
        _LOGGER.debug("Inserting ICE candidates into sdp answer")
        self.collect_ice_candidates = False
        for line_index, candidates in self.ice_candidates.items():
            if not candidates:
                continue
            candidates_dict = {
                int(candidate[10:12]): f"a={candidate}\r\n" for candidate in candidates
            }
            candidates_text = ("").join(dict(sorted(candidates_dict.items())).values())
            multi_text = f"a=mid:{line_index}"
            self.sdp = self.sdp.replace(multi_text, candidates_text + multi_text)

    async def handle_message(self, message_str):
        message = json_loads(message_str)
        method = message["method"]
        if method == "ice":
            self.handle_ice_message(
                message["body"]["ice"], message["body"]["mlineindex"]
            )
        elif method == "sdp":
            sdp = message["body"]["sdp"]
            self.sdp = sdp
            _LOGGER.debug("SDP answer received: %s", sdp)
        elif method == "notification":
            text = message["body"]["text"]
            _LOGGER.debug("Notification received: %s", text)
            if text == "camera_connected":
                camera_options = self.get_session_message(
                    "camera_options", {"stealth_mode": False}
                )
                _LOGGER.debug("Sending camera options: %s", camera_options)
                await self.websocket.send(json_dumps(camera_options))
        elif method == "session_created":
            self.session_id = message["body"]["session_id"]
            _LOGGER.debug(
                "Session created: "
                + self.session_id[:16]
                + "___"
                + self.session_id[-16:]
            )
        elif method == "close":
            _LOGGER.debug("Close: " + str(message["body"]["reason"]))
            self.do_ping = False
            await self.websocket.close()
        else:
            _LOGGER.debug("Message received with method: %s", method)
