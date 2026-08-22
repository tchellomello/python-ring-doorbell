# vim:sw=4:ts=4:et:
"""Python Ring Auth Class."""

from __future__ import annotations

import uuid
from asyncio import TimeoutError
from base64 import b64encode
from functools import cached_property
from json import loads as json_loads
from typing import TYPE_CHECKING, Any, Callable, ClassVar

from aiohttp import ClientError, ClientResponseError, ClientSession
from oauthlib.common import urldecode
from oauthlib.oauth2 import (
    LegacyApplicationClient,
    MissingTokenError,
    OAuth2Error,
    TokenExpiredError,
)

from ring_doorbell.const import NAMESPACE_UUID, TIMEOUT, OAuth
from ring_doorbell.exceptions import (
    AuthenticationError,
    Requires2FAError,
    RingError,
    RingTimeout,
)
from ring_doorbell.util import _DeprecatedSyncApiHandler


def _basic_auth_header(login: str, password: str) -> str:
    """Return the value of an HTTP Basic ``Authorization`` header.

    ``aiohttp.BasicAuth`` is deprecated and goes away in aiohttp 4.0. Its
    replacement, ``aiohttp.encode_basic_auth()``, needs aiohttp 3.14, which
    aioresponses does not support yet.
    """
    return "Basic " + b64encode(f"{login}:{password}".encode()).decode()


class Auth:
    """A Python Auth class for Ring."""

    def __init__(
        self,
        user_agent: str,
        token: dict[str, Any] | None = None,
        token_updater: Callable[[dict[str, Any]], None] | None = None,
        hardware_id: str | None = None,
        *,
        http_client_session: ClientSession | None = None,
    ) -> None:
        """Initialise the auth class.

        :type token: Optional[Dict[str, str]]
        :type token_updater: Optional[Callable[[str], None]]
        """
        self.user_agent = user_agent

        if hardware_id:
            self.hardware_id = hardware_id
        else:
            # Generate a UUID that will stay the same
            # for this physical device to prevent
            # multiple auth entries in ring.com
            self.hardware_id = str(
                uuid.uuid5(uuid.UUID(NAMESPACE_UUID), str(uuid.getnode()) + user_agent)
            )

        self.device_model = "ring-doorbell:" + user_agent
        self.token_updater = token_updater
        self._token: dict[str, Any] = token or {}
        self._local_session: ClientSession | None = None
        self.http_client_session = http_client_session
        self._oauth_client = LegacyApplicationClient(
            client_id=OAuth.CLIENT_ID, token=token
        )
        self._auth_header = _basic_auth_header(OAuth.CLIENT_ID, "")

    @property
    def _session(self) -> ClientSession:
        if self.http_client_session:
            return self.http_client_session
        if self._local_session is None:
            self._local_session = ClientSession()
        return self._local_session

    async def async_fetch_token(
        self, username: str, password: str, otp_code: str | None = None
    ) -> dict[str, Any]:
        """Fetch initial token with username/password & 2FA.

        :type username: str
        :type password: str
        :type otp_code: str.
        """
        headers = {
            "User-Agent": self.user_agent,
            "hardware_id": self.hardware_id,
            "Authorization": self._auth_header,
        }

        if otp_code:
            headers["2fa-support"] = "true"
            headers["2fa-code"] = otp_code

        try:
            body = self._oauth_client.prepare_request_body(
                username, password, scope=OAuth.SCOPE, include_client_id=True
            )
            data = dict(urldecode(body))
            resp = await self._session.request(
                "POST",
                OAuth.ENDPOINT,
                data=data,
                headers=headers,
            )
            async with resp:
                text = await resp.text()
            self._token = self._oauth_client.parse_request_body_response(
                text, scope=OAuth.SCOPE
            )
        except MissingTokenError as ex:
            raise Requires2FAError from ex
        except OAuth2Error as ex:
            raise AuthenticationError(ex) from ex

        if self.token_updater is not None:
            self.token_updater(self._token)

        return self._token

    async def async_refresh_tokens(self) -> dict[str, Any]:
        """Refresh the auth tokens."""
        try:
            headers = {
                "Accept": "application/json",
                "Content-Type": ("application/x-www-form-urlencoded;charset=UTF-8"),
                "Authorization": self._auth_header,
            }
            body = self._oauth_client.prepare_refresh_body(
                refresh_token=self._token["refresh_token"]
            )
            data = dict(urldecode(body))
            resp = await self._session.request(
                "POST", OAuth.ENDPOINT, data=data, headers=headers
            )
            async with resp:
                text = await resp.text()
            self._token = self._oauth_client.parse_request_body_response(
                text, scope=OAuth.SCOPE
            )
        except OAuth2Error as ex:
            raise AuthenticationError(ex) from ex

        if self.token_updater is not None:
            self.token_updater(self._token)

        return self._token

    def get_hardware_id(self) -> str:
        """Get hardware ID."""
        return self.hardware_id

    def get_device_model(self) -> str:
        """Get device model."""
        return self.device_model

    async def async_close(self) -> None:
        """Close aiohttp session."""
        session = self._local_session
        self._local_session = None
        if session:
            await session.close()

    class Response:
        """Class for returning responses."""

        def __init__(self, content: bytes, status_code: int) -> None:
            """Initialise thhe repsonse class."""
            self.content = content
            self.status_code = status_code

        @property
        def text(self) -> str:
            """Response as text."""
            return self.content.decode()

        def json(self) -> Any:
            """Response as loaded json."""
            return json_loads(self.text)

    async def async_query(  # noqa: C901, PLR0913
        self,
        url: str,
        method: str = "GET",
        extra_params: dict[str, Any] | None = None,
        data: bytes | None = None,
        json: dict[Any, Any] | None = None,
        timeout: float | None = None,
        *,
        raise_for_status: bool = True,
    ) -> Auth.Response:
        """Query data from Ring API."""
        if timeout is None:
            timeout = TIMEOUT

        params = {}
        if extra_params:
            params.update(extra_params)

        kwargs: dict[str, Any] = {
            "params": params,
            "timeout": timeout,
        }
        headers = {"User-Agent": self.user_agent, "hardware_id": self.get_hardware_id()}
        # Ring servers started requiring a null json value for PUT requests in 2024-10
        if json is not None or method == "PUT":
            kwargs["json"] = json
            headers["Content-Type"] = "application/json"

        try:
            try:
                url, headers, data = self._oauth_client.add_token(
                    url,
                    http_method=method,
                    body=data,
                    headers=headers,
                )

                resp = await self._session.request(
                    method, url, headers=headers, data=data, **kwargs
                )
            except TokenExpiredError:
                self._token = await self.async_refresh_tokens()
                url, headers, data = self._oauth_client.add_token(
                    url,
                    http_method=method,
                    body=data,
                    headers=headers,
                )
                resp = await self._session.request(
                    method, url, headers=headers, data=data, **kwargs
                )
        except AuthenticationError:
            raise  # refresh_tokens will return this error if not valid
        except TimeoutError as ex:
            msg = f"Timeout error during query of url {url}: {ex}"
            raise RingTimeout(msg) from ex
        except ClientError as ex:
            msg = f"aiohttp Client error during query of url {url}: {ex}"
            raise RingError(msg) from ex
        except Exception as ex:
            msg = f"Unknown error during query of url {url}: {ex}"
            raise RingError(msg) from ex

        async with resp:
            if resp.status == 401:
                # Check whether there's an issue with the token grant
                self._token = await self.async_refresh_tokens()

            if raise_for_status:
                try:
                    resp.raise_for_status()
                except ClientResponseError as ex:
                    msg = (
                        f"HTTP error with status code {resp.status} "
                        f"during query of url {url}: {ex}"
                    )
                    raise RingError(msg) from ex

            response_data = await resp.read()
        return Auth.Response(response_data, resp.status)

    @cached_property
    def _dep_handler(self) -> _DeprecatedSyncApiHandler:
        return _DeprecatedSyncApiHandler(self)

    DEPRECATED_API_QUERIES: ClassVar = {
        "fetch_token",
        "refresh_tokens",
        "close",
        "query",
    }

    if not TYPE_CHECKING:

        def __getattr__(self, name: str) -> Any:
            """Get a deprecated attribute or raise an error."""
            if name in self.DEPRECATED_API_QUERIES:
                return self._dep_handler.get_api_query(self, name)
            msg = f"{self.__class__.__name__} has no attribute {name!r}"
            raise AttributeError(msg)
