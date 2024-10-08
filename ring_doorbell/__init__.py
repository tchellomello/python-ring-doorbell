"""Python Package for interacting with Ring devices."""

from importlib.metadata import version

__version__ = version("ring_doorbell")

from ring_doorbell.auth import Auth
from ring_doorbell.chime import RingChime
from ring_doorbell.const import RingCapability, RingEventKind
from ring_doorbell.doorbot import RingDoorBell
from ring_doorbell.event import RingEvent
from ring_doorbell.exceptions import (
    AuthenticationError,
    Requires2FAError,
    RingError,
    RingTimeout,
)
from ring_doorbell.generic import RingGeneric
from ring_doorbell.group import RingLightGroup
from ring_doorbell.listen import RingEventListener, RingEventListenerConfig
from ring_doorbell.other import RingOther
from ring_doorbell.ring import Ring, RingDevices
from ring_doorbell.stickup_cam import RingStickUpCam

__all__ = [
    "Ring",
    "Auth",
    "RingDevices",
    "RingChime",
    "RingCapability",
    "RingEventKind",
    "RingStickUpCam",
    "RingLightGroup",
    "RingDoorBell",
    "RingOther",
    "RingEvent",
    "RingEventListener",
    "RingEventListenerConfig",
    "RingError",
    "AuthenticationError",
    "Requires2FAError",
    "RingTimeout",
    "RingGeneric",
    "RingEvent",
]
