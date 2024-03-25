# vim:sw=4:ts=4:et:
"""Python Ring Doorbell module."""
import logging
from itertools import chain
from time import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ring_doorbell import RingEvent
from ring_doorbell.auth import Auth
from ring_doorbell.chime import RingChime
from ring_doorbell.doorbot import RingDoorBell
from ring_doorbell.exceptions import RingError
from ring_doorbell.generic import RingGeneric
from ring_doorbell.group import RingLightGroup
from ring_doorbell.other import RingOther
from ring_doorbell.stickup_cam import RingStickUpCam

from .const import (
    API_URI,
    API_VERSION,
    DEVICES_ENDPOINT,
    DINGS_ENDPOINT,
    GROUPS_ENDPOINT,
    NEW_SESSION_ENDPOINT,
)

_logger = logging.getLogger(__name__)


class Ring:
    """A Python Abstraction object to Ring Door Bell."""

    def __init__(self, auth: Auth):
        """Initialize the Ring object."""
        self.auth: Auth = auth
        self.session = None
        self.subscription = None
        self.devices_data: Dict[str, Dict[int, Dict[str, Any]]] = {}
        self.chime_health_data = None
        self.doorbell_health_data = None
        self.dings_data: Dict[Any, Any] = {}
        self.push_dings_data: List[RingEvent] = []
        self.groups_data: Dict[str, Dict[str, Any]] = {}
        self.init_loop = None

    def update_data(self) -> None:
        """Update all data."""
        self.auth._run_async_on_event_loop(self.async_update_data())

    async def async_update_data(self) -> None:
        """Update all data."""
        await self._async_update_data()

    async def _async_update_data(self) -> None:
        if self.session is None:
            await self.async_create_session()

        await self.async_update_devices()

        await self.async_update_dings()

        await self.async_update_groups()

    def add_event_to_dings_data(self, ring_event: RingEvent) -> None:
        # Purge expired push_dings
        now = time()
        self.push_dings_data = [
            re for re in self.push_dings_data if now < re.now + re.expires_in
        ]
        self.push_dings_data.append(ring_event)

    def create_session(self) -> None:
        """Create a new Ring session."""
        self.auth._run_async_on_event_loop(self.async_create_session())

    async def async_create_session(self) -> None:
        """Create a new Ring session."""
        session_post_data = {
            "device": {
                "hardware_id": self.auth.get_hardware_id(),
                "metadata": {
                    "api_version": API_VERSION,
                    "device_model": self.auth.get_device_model(),
                },
                "os": "android",
            }
        }
        resp = await self._async_query(
            NEW_SESSION_ENDPOINT,
            method="POST",
            json=session_post_data,
        )
        self.session = resp.json()

    def update_devices(self) -> None:
        """Update device data."""
        self.auth._run_async_on_event_loop(self.async_update_devices())

    async def async_update_devices(self) -> None:
        """Update device data."""
        if self.session is None:
            await self.async_create_session()

        resp = await self._async_query(DEVICES_ENDPOINT)
        data: Dict[Any, Any] = resp.json()

        # Index data by device ID.
        self.devices_data = {
            device_type: {obj["id"]: obj for obj in devices}
            for device_type, devices in data.items()
        }

    def update_dings(self) -> None:
        """Update dings data."""
        self.auth._run_async_on_event_loop(self.async_update_dings())

    async def async_update_dings(self) -> None:
        """Update dings data."""
        if self.session is None:
            await self.async_create_session()

        resp = await self._async_query(DINGS_ENDPOINT)
        self.dings_data = resp.json()

    def update_groups(self) -> None:
        """Update groups data."""
        self.auth._run_async_on_event_loop(self.async_update_groups())

    async def async_update_groups(self) -> None:
        """Update groups data."""
        if self.session is None:
            await self.async_create_session()
        # Get all locations
        locations = set()
        for devices in self.devices_data.values():
            for dev in devices.values():
                if "location_id" in dev:
                    locations.add(dev["location_id"])

        # Query for groups
        self.groups_data = {}
        locations.discard(None)
        for location in locations:
            resp = await self._async_query(GROUPS_ENDPOINT.format(location))
            data = resp.json()
            if data["device_groups"]:
                for group in data["device_groups"]:
                    self.groups_data[group["device_group_id"]] = group

    def query(
        self,
        url: str,
        method: str = "GET",
        extra_params: Optional[Dict[str, Any]] = None,
        data: Optional[bytes] = None,
        json: Optional[Dict[Any, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Auth.Response:
        """Query data from Ring API."""
        return self.auth._run_async_on_event_loop(
            self._async_query(url, method, extra_params, data, json, timeout)
        )

    async def async_query(
        self,
        url: str,
        method: str = "GET",
        extra_params: Optional[Dict[str, Any]] = None,
        data: Optional[bytes] = None,
        json: Optional[Dict[Any, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Auth.Response:
        """Query data from Ring API."""
        if self.session is None:
            await self.async_create_session()
        return await self._async_query(url, method, extra_params, data, json, timeout)

    async def _async_query(
        self,
        url: str,
        method: str = "GET",
        extra_params: Optional[Dict[str, Any]] = None,
        data: Optional[bytes] = None,
        json: Optional[Dict[Any, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Auth.Response:
        _logger.debug(
            "url: %s\nmethod: %s\njson: %s\ndata: %s\n extra_params: %s",
            url,
            method,
            json,
            data,
            extra_params,
        )
        response = await self.auth.async_query(
            API_URI + url,
            method=method,
            extra_params=extra_params,
            data=data,
            json=json,
            timeout=timeout,
        )
        _logger.debug("response_text %s", response.text)
        return response

    def devices(self) -> "RingDevices":
        """Get all devices."""
        return RingDevices(self, self.devices_data)

    def get_device_list(self) -> Sequence[RingGeneric]:
        """Get a combined list of all devices."""
        devices = self.devices()
        return list(
            chain(
                devices["doorbots"],
                devices["authorized_doorbots"],
                devices["stickup_cams"],
                devices["chimes"],
                devices["other"],
            )
        )

    def get_device_by_name(self, device_name: str) -> Optional[RingGeneric]:
        """Return a device using it's name."""
        all_devices = self.get_device_list()
        names_to_idx = {device.name: idx for (idx, device) in enumerate(all_devices)}
        device = (
            None
            if device_name not in names_to_idx
            else all_devices[names_to_idx[device_name]]
        )
        return device

    def get_video_device_by_name(self, device_name: str) -> Optional[RingDoorBell]:
        """Return a device using it's name."""
        video_devices = self.video_devices()
        names_to_idx = {device.name: idx for (idx, device) in enumerate(video_devices)}
        device = (
            None
            if device_name not in names_to_idx
            else video_devices[names_to_idx[device_name]]
        )
        return device

    def get_device_by_api_id(self, device_api_id: int) -> Optional[RingGeneric]:
        """Return a device using it's id."""
        all_devices = self.get_device_list()
        api_id_to_idx = {
            device.device_api_id: idx for (idx, device) in enumerate(all_devices)
        }
        device = (
            None
            if device_api_id not in api_id_to_idx
            else all_devices[api_id_to_idx[device_api_id]]
        )
        return device

    def video_devices(self) -> Sequence[RingDoorBell]:
        """Get all devices."""
        devices = self.devices()
        return list(
            chain(devices.doorbots, devices.authorized_doorbots, devices.stickup_cams)
        )

    def groups(self) -> Mapping[str, RingLightGroup]:
        """Get all groups."""
        groups = {}

        for group_id in self.groups_data:
            groups[group_id] = RingLightGroup(self, group_id)

        return groups

    def active_alerts(self) -> Sequence[RingEvent]:
        """Get active alerts."""
        now = time()
        # Purge expired push_dings
        self.push_dings_data = [
            re for re in self.push_dings_data if now < re.now + re.expires_in
        ]
        # Get unique id dictionary
        alerts: Dict[Tuple[int, int, str], RingEvent] = {}
        for re in self.push_dings_data:
            key = (re.doorbot_id, re.id, re.kind)
            if key not in alerts or re.now > alerts[key].now:
                alerts[key] = re

        for ding_data in self.dings_data:
            expires_at = ding_data.get("now") + ding_data.get("expires_in")

            if now < expires_at:
                re = RingEvent(
                    id=ding_data["id"],
                    doorbot_id=ding_data["doorbot_id"],
                    device_name=ding_data["doorbot_description"],
                    device_kind=ding_data["device_kind"],
                    now=ding_data["now"],
                    expires_in=ding_data["expires_in"],
                    kind=ding_data["kind"],
                    state=ding_data["state"],
                )
                key = (re.doorbot_id, re.id, re.kind)
                if key not in alerts or re.now > alerts[key].now:
                    alerts[key] = re

        return list(alerts.values())


class RingDevices:
    """Class to represent collection of devices."""

    def __init__(
        self, ring: "Ring", devices_data: Dict[str, Dict[int, Dict[str, Any]]]
    ) -> None:
        self._stickup_cams: List[RingStickUpCam] = []
        self._chimes: List[RingChime] = []
        self._doorbots: List[RingDoorBell] = []
        self._authorized_doorbots: List[RingDoorBell] = []
        self._other: List[RingOther] = []

        for device_type, devices in devices_data.items():
            if device_type == "stickup_cams":
                self._stickup_cams = [
                    RingStickUpCam(ring, device_id) for device_id in devices
                ]
            if device_type == "chimes":
                self._chimes = [RingChime(ring, device_id) for device_id in devices]
            if device_type == "doorbots":
                self._doorbots = [
                    RingDoorBell(ring, device_id) for device_id in devices
                ]
            if device_type == "authorized_doorbots":
                self._authorized_doorbots = [
                    RingDoorBell(ring, device_id, shared=True) for device_id in devices
                ]
            if device_type == "other":
                self._other = [
                    RingOther(ring, device_id, shared=True) for device_id in devices
                ]

    def __getitem__(self, device_type: str) -> Sequence[RingGeneric]:
        if device_type == "stickup_cams":
            return self._stickup_cams
        if device_type == "chimes":
            return self._chimes
        if device_type == "doorbots":
            return self._doorbots
        if device_type == "authorized_doorbots":
            return self._authorized_doorbots
        if device_type == "other":
            return self._other
        raise RingError(f"Invalid device_type {device_type}")

    def __iter__(self) -> Iterable:
        return iter(
            ["stickup_cams", "chimes", "doorbots", "authorized_doorbots", "other"]
        )

    @property
    def stickup_cams(self) -> Sequence[RingStickUpCam]:
        return self._stickup_cams

    @property
    def chimes(self) -> Sequence[RingChime]:
        return self._chimes

    @property
    def doorbots(self) -> Sequence[RingDoorBell]:
        return self._doorbots

    @property
    def authorized_doorbots(self) -> Sequence[RingDoorBell]:
        return self._authorized_doorbots

    @property
    def other(self) -> Sequence[RingOther]:
        return self._other
