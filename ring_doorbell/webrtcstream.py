"""Python Ring Doorbell RTC Stream handler.

This module is currently experimental and requires a webrtc enabled client
to function.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import ssl
import time
import uuid
from dataclasses import dataclass
from json import dumps as json_dumps
from json import loads as json_loads
from typing import TYPE_CHECKING, Any, Callable

from async_timeout import timeout as asyncio_timeout
from typing_extensions import TypeAlias
from websockets.asyncio.client import connect

from ring_doorbell.const import (
    APP_API_URI,
    RTC_STREAMING_TICKET_ENDPOINT,
    RTC_STREAMING_WEB_SOCKET_ENDPOINT,
)
from ring_doorbell.exceptions import RingError

if TYPE_CHECKING:
    from collections.abc import Coroutine

    from websockets.asyncio.client import ClientConnection

    from .ring import Ring

_LOGGER = logging.getLogger(__name__)

SDP_ANSWER_TIMEOUT = 1


@dataclass
class RingWebRtcMessage:
    """Class for async on_message callback."""

    answer: str | None = None
    candidate: str | None = None
    sdp_m_line_index: int | None = None
    error_code: str | None = None
    error_message: str | None = None
    session_id: str | None = None


RingWebRtcMessageCallback: TypeAlias = Callable[[RingWebRtcMessage], None]


class RingWebRtcStream:
    """Class to handle a Web RTC Stream."""

    PING_TIME_SECONDS = 5

    def __init__(
        self,
        ring: Ring,
        device_api_id: int,
        *,
        keep_alive_timeout: int | None = 30,
        on_message_callback: RingWebRtcMessageCallback | None = None,
        on_close_callback: Callable[[], Coroutine[Any, Any, None]] | None = None,
    ) -> None:
        """Initialise the class."""
        self._ring = ring
        self.device_api_id = device_api_id
        self.sdp_offer: str | None = None
        self.sdp: str | None = None
        self.websocket: ClientConnection | None = None
        self.is_alive = True
        self.ping_task: asyncio.Task | None = None
        self.read_task: asyncio.Task | None = None
        self._close_task: asyncio.Task | None = None
        self.ice_candidates: dict[int, list[str]] = {0: [], 1: [], 2: [], 3: []}
        self.collect_ice_candidates = False
        self.ssl_context: ssl.SSLContext | None = None
        self._sdp_answer_event = asyncio.Event()
        self._keep_alive_timeout = keep_alive_timeout
        self._last_keep_alive: float | None = None
        self._on_close_callback = on_close_callback
        self._on_message_callback = on_message_callback
        self.session_id: str | None = None
        self._offered_event = asyncio.Event()

    @staticmethod
    def get_sdp_session_id(sdp_offer: str) -> str | None:
        """Return the sdp session id from the offer."""
        try:
            lines = sdp_offer.split("\n")
            for line in lines:
                if line[0] == "o":
                    origin = line.split("=")[1]
                    break
            return origin.split(" ")[1]
        except Exception:
            _LOGGER.exception("Error getting session id from offer: %s", sdp_offer)
            return None

    async def generate(self, sdp_offer: str) -> str | None:
        """Generate the RTC stream."""
        self.sdp_offer = sdp_offer
        await self._generate(sdp_offer)

        if self._on_message_callback:
            return None

        if self.collect_ice_candidates:
            _LOGGER.debug(
                "Waiting %s seconds for ice candidates",
                SDP_ANSWER_TIMEOUT,
            )
            await asyncio.sleep(SDP_ANSWER_TIMEOUT)
            self.insert_ice_candidates()
        else:
            async with asyncio_timeout(SDP_ANSWER_TIMEOUT):
                await self._sdp_answer_event.wait()

        if not self.sdp:
            exmsg = "Unable to generate RTC stream in time"
            await self.close()
            raise RingError(exmsg)
        _LOGGER.debug("Returning SDP answer: %s", self.sdp)
        return self.sdp

    async def _generate(self, sdp_offer: str) -> None:
        """Generate the RTC stream."""
        try:
            _LOGGER.debug("Generating stream with sdp offer: %s", sdp_offer)
            req = await self._ring.async_query(
                RTC_STREAMING_TICKET_ENDPOINT,
                method="POST",
                base_uri=APP_API_URI,
            )
            ticket = req.json()["ticket"]

            _LOGGER.debug(
                "Received RTC streaming ticket %s from endpoint, creating websocket",
                ticket,
            )
            ws_uri = RTC_STREAMING_WEB_SOCKET_ENDPOINT.format(uuid.uuid4(), ticket)
            loop = asyncio.get_running_loop()

            if not self.ssl_context:
                # create_default_context() blocks the event loop
                self.ssl_context = await loop.run_in_executor(
                    None, ssl.create_default_context
                )
            self.websocket = await connect(
                ws_uri,
                user_agent_header="android:com.ringapp",
                ssl=self.ssl_context,
            )

            self.dialog_id = str(uuid.uuid4())
            offer_msg = {
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
                "Connected to RTC streaming websocket, sending live_view offer msg: %s",
                offer_msg,
            )
            _LOGGER.debug("Starting reader task")
            self.read_task = asyncio.create_task(self.reader())

            await self.websocket.send(json_dumps(offer_msg))

            self._offered_event.set()

        except Exception as ex:
            exmsg = "Error generating RTC stream"
            raise RingError(exmsg, ex) from ex

    async def _activate(self) -> None:
        if TYPE_CHECKING:
            assert self.websocket
        activate_msg = self.get_session_message("activate_session", {})
        _LOGGER.debug("Sending activate_session message: %s", activate_msg)
        await self.websocket.send(json_dumps(activate_msg))

        self._last_keep_alive = time.time()
        self.ping_task = asyncio.create_task(self.pinger())

    async def on_ice_candidate(self, candidate: str, m_line_index: int) -> None:
        """Send an ICE candidate."""
        async with asyncio_timeout(10):
            await self._offered_event.wait()

        assert self.websocket  # noqa: S101

        body = {
            "doorbot_id": self.device_api_id,
            "ice": candidate,
            "mlineindex": m_line_index,
        }
        # Set the session if it's been created.
        if self.session_id:
            body["session_id"] = self.session_id
        ice_msg = {
            "method": "ice",
            "dialog_id": self.dialog_id,
            "body": body,
        }
        _LOGGER.debug(
            "Sending ice candidate for mlineindex %s: %s", m_line_index, candidate
        )
        await self.websocket.send(json_dumps(ice_msg))

    async def keep_alive(self) -> None:
        """Keep alive the rtc stream."""
        self._last_keep_alive = time.time()

    def get_session_message(self, method: str, body: dict[str, Any]) -> dict[str, Any]:
        """Get a message to send to the session."""
        return {
            "method": method,
            "dialog_id": self.dialog_id,
            "body": {
                **body,
                "doorbot_id": self.device_api_id,
                "session_id": self.session_id,
            },
        }

    async def reader(self) -> None:
        """Read messages from the websocket."""
        if TYPE_CHECKING:
            assert self.websocket
        async for message in self.websocket:
            if TYPE_CHECKING:
                assert isinstance(message, str)
            await self.handle_message(message)

    async def pinger(self) -> None:
        """Ping to keep the session alive."""
        if TYPE_CHECKING:
            assert self.websocket
            assert self._last_keep_alive

        while self.is_alive and (
            self._keep_alive_timeout is None
            or (time.time() - self._last_keep_alive) <= self._keep_alive_timeout
        ):
            await asyncio.sleep(self.PING_TIME_SECONDS)
            ping = self.get_session_message("ping", {})
            await self.websocket.send(json_dumps(ping))

    def handle_ice_message(self, message: dict) -> None:
        """Handle an ice candidate message."""
        ice_candidate = message["body"]["ice"]
        multi_line_index = message["body"]["mlineindex"]
        if self._on_message_callback:
            ice_message = RingWebRtcMessage(
                candidate=ice_candidate, sdp_m_line_index=multi_line_index
            )
            self._on_message_callback(ice_message)
        elif self.collect_ice_candidates:
            _LOGGER.debug(
                "Ice candidate received, multi_line_index: %s candidate: %s",
                multi_line_index,
                ice_candidate,
            )
            self.ice_candidates[int(multi_line_index)].append(ice_candidate)

    async def handle_answer_message(self, message: dict) -> None:
        """Handle an sdp answer message."""
        sdp = message["body"]["sdp"]
        _LOGGER.debug("SDP answer received: %s", sdp)
        self.sdp = sdp
        self.force_correct_sdp_answer()
        self._sdp_answer_event.set()

        if self._on_message_callback:
            answer_message = RingWebRtcMessage(answer=self.sdp)
            self._on_message_callback(answer_message)

        await self._activate()

    async def handle_close_message(self, message: dict) -> None:
        """Handle an sdp answer message."""
        reason = message["body"]["reason"]
        reason_code = reason["code"]
        reason_message = reason["text"]
        _LOGGER.debug("Close message received: %s", str(reason))
        self.is_alive = False
        await self._close(closed_by_self=True)
        if self._on_message_callback:
            error_message = RingWebRtcMessage(
                error_code=reason_code, error_message=reason_message
            )
            self._on_message_callback(error_message)

    def force_correct_sdp_answer(self) -> None:
        """Force the sdp response to have the valid answer.

        The Ring WebRTC Stream responses to certain offers do not
        follow the spec defined in https://www.ietf.org/rfc/rfc3264.txt
        An offer of recvonly must be answered with sendonly or inactive.
        """
        _LOGGER.debug("Attempt to fix sdp answer...")
        if isinstance(self.sdp, str) and isinstance(self.sdp_offer, str):
            sdp_kinds = ["audio", "video", "application"]
            sdp_directions = ["sendrecv", "sendonly", "recvonly", "inactive"]
            sdp_pattern = (
                "m=(?P<kind>{})(.|\n)+?a=(?P<direction>{})(\r|\n|\r\n)".format(
                    "|".join(sdp_kinds), "|".join(sdp_directions)
                )
            )

            sdp_direction_offers = re.finditer(sdp_pattern, self.sdp_offer)
            sdp_answers = re.finditer(sdp_pattern, self.sdp)

            for offer in sdp_direction_offers:
                for answer in sdp_answers:
                    if (
                        offer.group("kind") == answer.group("kind")
                        and offer.group("direction") == "recvonly"
                        and answer.group("direction") == "sendrecv"
                    ):
                        correct_answer = re.sub(
                            "a=sendrecv", "a=sendonly", answer.group(0)
                        )
                        _LOGGER.debug("Replacing answer with: %s", str(correct_answer))
                        self.sdp = self.sdp.replace(answer.group(0), correct_answer)

    def insert_ice_candidates(self) -> None:
        """Insert an ice candidate into the sdp answer.

        In 2023 the ring api did not return the ice servers in the sdp answer
        and they had to be added as they were received on the web socket.
        As of Sep 2024 they are coming back with the initial sdp answer.
        """
        if TYPE_CHECKING:
            assert self.sdp
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

    def sync_close(self) -> None:
        """Close a WebRTC session."""
        if self.is_alive and not self._close_task:
            self._close_task = asyncio.create_task(self.close())

    async def close(self) -> None:
        """Close the rtc stream."""
        _LOGGER.debug("Closing the RTC Stream")
        await self._close(closed_by_self=False)
        self._close_task = None

    async def _close(self, *, closed_by_self: bool) -> None:
        """Close the stream."""
        self.session_id = None
        if closed_by_self and (close_cb := self._on_close_callback):
            self._on_close_callback = None
            await close_cb()
        self.is_alive = False
        if ping_task := self.ping_task:
            self.ping_task = None
            if not ping_task.done():
                ping_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await ping_task
        if websocket := self.websocket:
            self.websocket = None
            await websocket.close()
        if read_task := self.read_task:
            self.read_task = None
            if read_task is asyncio.current_task():
                return
            if not read_task.done():
                await read_task

    async def handle_message(self, message_str: str) -> None:  # noqa: C901, PLR0912
        """Handle a message from the web socket."""
        if TYPE_CHECKING:
            assert self.websocket
        message = json_loads(message_str)
        method = message["method"]
        if method == "ice":
            self.handle_ice_message(message)
        elif method == "sdp":
            await self.handle_answer_message(message)
        elif method == "notification":
            text = message["body"]["text"]
            if text == "camera_connected":
                _LOGGER.debug("Notification received: %s", text)
                camera_options = self.get_session_message(
                    "camera_options", {"stealth_mode": False}
                )
                _LOGGER.debug("Sending camera options: %s", camera_options)
                await self.websocket.send(json_dumps(camera_options))
            else:
                _LOGGER.debug("Received notification: %s", message)
        elif method == "session_created":
            body = message.get("body") or {}
            if not (session_id := body.get("session_id")):
                _LOGGER.warning(
                    "Ignoring session_created without session_id (body keys: %s)",
                    sorted(body),
                )
                return
            self.session_id = session_id
            if TYPE_CHECKING:
                assert self.session_id
            _LOGGER.debug(
                "Session created: %s___%s", self.session_id[:16], self.session_id[-16:]
            )
        elif method == "close":
            await self.handle_close_message(message)
        elif method == "pong":
            _LOGGER.debug("Pong message received")
        elif method == "camera_started":
            _LOGGER.debug("camera_started message received")
        elif method == "camera_options":
            _LOGGER.debug("camera_options message received: %s", message["body"])
        else:
            _LOGGER.debug("Unknown message received with method: %s", method)
