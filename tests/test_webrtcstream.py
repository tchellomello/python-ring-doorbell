"""Tests for the Ring WebRTC stream handler."""

import asyncio
from unittest.mock import MagicMock

from ring_doorbell.webrtcstream import RingWebRtcStream


async def test_session_created_without_session_id_is_ignored(caplog):
    """Test malformed session-created messages do not break the stream."""
    stream = RingWebRtcStream(MagicMock(), 123)

    await stream.handle_message('{"method":"session_created","body":{}}')

    assert stream.session_id is None
    assert "without session_id" in caplog.text


async def test_close_from_reader_does_not_await_itself():
    """Test closing from the reader task does not await the same task."""
    stream = RingWebRtcStream(MagicMock(), 123)
    stream.read_task = asyncio.current_task()

    await stream._close(closed_by_self=False)

    assert stream.read_task is None
    assert stream.is_alive is False
