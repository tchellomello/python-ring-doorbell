# vim:sw=4:ts=4:et:
"""Python Ring Doorbell module."""

from __future__ import annotations

import logging
from itertools import chain
from time import time
from typing import TYPE_CHECKING, Any, Iterator, Mapping, Sequence

from ring_doorbell import RingEvent
from ring_doorbell.chime import RingChime
from ring_doorbell.doorbot import RingDoorBell
from ring_doorbell.exceptions import RingError
from ring_doorbell.group import RingLightGroup
from ring_doorbell.other import RingOther
from ring_doorbell.stickup_cam import RingStickUpCam

from .const import (
    API_URI,
    API_VERSION,
    DEVICES_ENDPOINT,
    DINGS_ENDPOINT,
    GROUPS_ENDPOINT,
    INTERCOM_KINDS,
    NEW_SESSION_ENDPOINT,
)

if TYPE_CHECKING:
    from ring_doorbell.auth import Auth
    from ring_doorbell.generic import RingGeneric

_logger = logging.getLogger(__name__)


class Ring:
    """A Python Abstraction object to Ring Door Bell."""

    def __init__(self, auth: Auth) -> None:
        """Initialize the Ring object."""
        self.auth: Auth = auth
        self.session = None
        self.subscription = None
        self.devices_data: dict[str, dict[int, dict[str, Any]]] = {}
        self.chime_health_data = None
        self.doorbell_health_data = None
        self.dings_data: dict[Any, Any] = {}
        self.push_dings_data: list[RingEvent] = []
        self.groups_data: dict[str, dict[str, Any]] = {}
        self.init_loop = None

    def update_data(self) -> None:
        """Update all data."""
        self.auth.run_async_on_event_loop(self.async_update_data())

    async def async_update_data(self) -> None:
        """Update all data."""
        await self._async_update_data()

    async def _async_update_data(self) -> None:
        if self.session is None:
            await self.async_create_session()

        await self.async_update_devices()

        await self.async_update_dings()

        await self.async_update_groups()

    def _add_event_to_dings_data(self, ring_event: RingEvent) -> None:
        # Purge expired push_dings
        now = time()
        self.push_dings_data = [
            re for re in self.push_dings_data if now < re.now + re.expires_in
        ]
        self.push_dings_data.append(ring_event)

    def create_session(self) -> None:
        """Create a new Ring session."""
        self.auth.run_async_on_event_loop(self.async_create_session())

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
        self.auth.run_async_on_event_loop(self.async_update_devices())

    async def async_update_devices(self) -> None:
        """Update device data."""
        if self.session is None:
            await self.async_create_session()

        resp = await self._async_query(DEVICES_ENDPOINT)
        data: dict[Any, Any] = resp.json()

        # Index data by device ID.
        self.devices_data = {
            device_type: {obj["id"]: obj for obj in devices}
            for device_type, devices in data.items()
        }

    def update_dings(self) -> None:
        """Update dings data."""
        self.auth.run_async_on_event_loop(self.async_update_dings())

    async def async_update_dings(self) -> None:
        """Update dings data."""
        if self.session is None:
            await self.async_create_session()

        resp = await self._async_query(DINGS_ENDPOINT)
        self.dings_data = resp.json()

    def update_groups(self) -> None:
        """Update groups data."""
        self.auth.run_async_on_event_loop(self.async_update_groups())

    async def async_update_groups(self) -> None:
        """Update groups data."""
        if self.session is None:
            await self.async_create_session()
        # Get all locations
        locations = set()
        devices = self.devices()
        for device_type in devices:
            for dev in devices[device_type]:
                if dev.location_id is not None:
                    locations.add(dev.location_id)

        # Query for groups
        self.groups_data = {}
        for location in locations:
            resp = await self._async_query(GROUPS_ENDPOINT.format(location))
            data = resp.json()
            if data["device_groups"]:
                for group in data["device_groups"]:
                    self.groups_data[group["device_group_id"]] = group

    def query(  # noqa: PLR0913
        self,
        url: str,
        method: str = "GET",
        extra_params: dict[str, Any] | None = None,
        data: bytes | None = None,
        json: dict[Any, Any] | None = None,
        timeout: float | None = None,
    ) -> Auth.Response:
        """Query data from Ring API."""
        return self.auth.run_async_on_event_loop(
            self._async_query(url, method, extra_params, data, json, timeout)
        )

    async def async_query(  # noqa: PLR0913
        self,
        url: str,
        method: str = "GET",
        extra_params: dict[str, Any] | None = None,
        data: bytes | None = None,
        json: dict[Any, Any] | None = None,
        timeout: float | None = None,
    ) -> Auth.Response:
        """Query data from Ring API."""
        if self.session is None:
            await self.async_create_session()
        return await self._async_query(url, method, extra_params, data, json, timeout)

    async def _async_query(  # noqa: PLR0913
        self,
        url: str,
        method: str = "GET",
        extra_params: dict[str, Any] | None = None,
        data: bytes | None = None,
        json: dict[Any, Any] | None = None,
        timeout: float | None = None,
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

    def devices(self) -> RingDevices:
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

    def get_device_by_name(self, device_name: str) -> RingGeneric | None:
        """Return a device using it's name."""
        all_devices = self.get_device_list()
        names_to_idx = {device.name: idx for (idx, device) in enumerate(all_devices)}
        return (
            None
            if device_name not in names_to_idx
            else all_devices[names_to_idx[device_name]]
        )

    def get_video_device_by_name(self, device_name: str) -> RingDoorBell | None:
        """Return a device using it's name."""
        video_devices = self.video_devices()
        names_to_idx = {device.name: idx for (idx, device) in enumerate(video_devices)}
        return (
            None
            if device_name not in names_to_idx
            else video_devices[names_to_idx[device_name]]
        )

    def get_device_by_api_id(self, device_api_id: int) -> RingGeneric | None:
        """Return a device using it's id."""
        all_devices = self.get_device_list()
        api_id_to_idx = {
            device.device_api_id: idx for (idx, device) in enumerate(all_devices)
        }
        return (
            None
            if device_api_id not in api_id_to_idx
            else all_devices[api_id_to_idx[device_api_id]]
        )

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
        alerts: dict[tuple[int, int, str], RingEvent] = {}
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
        self, ring: Ring, devices_data: dict[str, dict[int, dict[str, Any]]]
    ) -> None:
        """Initialise the devices from the api response."""
        self._stickup_cams: list[RingStickUpCam] = []
        self._chimes: list[RingChime] = []
        self._doorbots: list[RingDoorBell] = []
        self._authorized_doorbots: list[RingDoorBell] = []
        self._other: list[RingOther] = []

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
                    RingOther(ring, device_id, shared=True)
                    for device_id, device in devices.items()
                    if (device_kind := device.get("kind"))
                    and device_kind in INTERCOM_KINDS
                ]
        self._all_devices = {
            device.id: device
            for device in chain(
                self._stickup_cams,
                self._chimes,
                self._doorbots,
                self._authorized_doorbots,
                self._other,
            )
        }

    def __getitem__(self, device_type: str) -> Sequence[RingGeneric]:
        """Get a generic device by type."""
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
        msg = f"Invalid device_type {device_type}"
        raise RingError(msg)

    def __iter__(self) -> Iterator[str]:
        """Device type iterator."""
        return iter(
            ["stickup_cams", "chimes", "doorbots", "authorized_doorbots", "other"]
        )

    @property
    def stickup_cams(self) -> Sequence[RingStickUpCam]:
        """The stickup cams."""
        return self._stickup_cams

    @property
    def chimes(self) -> Sequence[RingChime]:
        """The chimes."""
        return self._chimes

    @property
    def doorbots(self) -> Sequence[RingDoorBell]:
        """The doorbots."""
        return self._doorbots

    @property
    def authorized_doorbots(self) -> Sequence[RingDoorBell]:
        """The authorized_doorbots."""
        return self._authorized_doorbots

    @property
    def doorbells(self) -> Sequence[RingDoorBell]:
        """The doorbells, i.e. doorbots and authorized_doorbots combined."""
        return self._doorbots + self._authorized_doorbots

    @property
    def other(self) -> Sequence[RingOther]:
        """The other devices, i.e. intercoms."""
        return self._other

    @property
    def all_devices(self) -> Sequence[RingGeneric]:
        """All devices combined."""
        return list(self._all_devices.values())

    @property
    def video_devices(self) -> Sequence[RingDoorBell]:
        """The video devices, i.e. doorbells and stickup_cams."""
        return [*self._doorbots, *self._authorized_doorbots, *self._stickup_cams]

    def get_device(self, device_api_id: int) -> RingGeneric:
        """Get device by api id."""
        if device := self._all_devices.get(device_api_id):
            return device
        msg = f"device with id {device_api_id} not found"
        raise RingError(msg)

    def get_doorbell(self, device_api_id: int) -> RingDoorBell:
        """Get doorbell by api id."""
        if (
            (device := self._all_devices.get(device_api_id))
            and isinstance(device, RingDoorBell)
            and not issubclass(device.__class__, RingDoorBell)
        ):
            return device
        msg = f"doorbell with id {device_api_id} not found"
        raise RingError(msg)

    def get_stickup_cam(self, device_api_id: int) -> RingStickUpCam:
        """Get stickup_cam by api id."""
        if (device := self._all_devices.get(device_api_id)) and isinstance(
            device, RingStickUpCam
        ):
            return device
        msg = f"stickup_cam with id {device_api_id} not found"
        raise RingError(msg)

    def get_chime(self, device_api_id: int) -> RingChime:
        """Get chime by api id."""
        if (device := self._all_devices.get(device_api_id)) and isinstance(
            device, RingChime
        ):
            return device
        msg = f"chime with id {device_api_id} not found"
        raise RingError(msg)

    def get_other(self, device_api_id: int) -> RingOther:
        """Get other device by api id."""
        if (device := self._all_devices.get(device_api_id)) and isinstance(
            device, RingOther
        ):
            return device
        msg = f"other device with id {device_api_id} not found"
        raise RingError(msg)

    def get_video_device(self, device_api_id: int) -> RingDoorBell:
        """Get video capable device by api id."""
        if (device := self._all_devices.get(device_api_id)) and isinstance(
            device, RingDoorBell
        ):
            return device
        msg = f"video capable device with id {device_api_id} not found"
        raise RingError(msg)

    def __str__(self) -> str:
        """Get string representation of devices."""
        d = {dev_type: self.__getitem__(dev_type) for dev_type in self.__iter__()}
        return "{" + "\n".join(f"{k!r}: {v!r}," for k, v in d.items()) + "}"

    def __repr__(self) -> str:
        """Return repr of devices."""
        d = {dev_type: self.__getitem__(dev_type) for dev_type in self.__iter__()}
        return repr(d)
