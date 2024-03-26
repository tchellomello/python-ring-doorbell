# vim:sw=4:ts=4:et:
"""Python Ring Auth Class."""
import asyncio
import contextlib
import uuid
from json import loads as json_loads
from threading import Thread
from typing import Any, Callable, Coroutine, Dict, Optional

from aiohttp import BasicAuth, ClientSession
from oauthlib.common import urldecode
from oauthlib.oauth2 import (
    LegacyApplicationClient,
    MissingTokenError,
    OAuth2Error,
    TokenExpiredError,
)
from requests import HTTPError, Response, Timeout

from ring_doorbell.const import NAMESPACE_UUID, TIMEOUT, OAuth
from ring_doorbell.exceptions import (
    AuthenticationError,
    Requires2FAError,
    RingError,
    RingTimeout,
)


class Auth:
    """A Python Auth class for Ring"""

    def __init__(
        self,
        user_agent: str,
        token: Optional[Dict[str, Any]] = None,
        token_updater: Optional[Callable[[Dict[str, Any]], None]] = None,
        hardware_id: Optional[str] = None,
        http_client_session: Optional[ClientSession] = None,
    ) -> None:
        """
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
        self._token: Dict[str, Any] = token or {}
        self._local_session: Optional[ClientSession] = None
        self._http_client_session = http_client_session
        self._oauth_client = LegacyApplicationClient(
            client_id=OAuth.CLIENT_ID, token=token
        )
        self._auth = BasicAuth(OAuth.CLIENT_ID, "")
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._init_loop: Optional[asyncio.AbstractEventLoop] = None
        self._new_loop: Optional[asyncio.AbstractEventLoop] = None
        with contextlib.suppress(RuntimeError):
            self._init_loop = asyncio.get_running_loop()
        self._background_thread_loop: Optional[asyncio.AbstractEventLoop] = None

    @property
    def _session(self) -> ClientSession:
        if self._http_client_session:
            return self._http_client_session
        if self._local_session is None:
            self._local_session = ClientSession()
            self._loop = asyncio.get_running_loop()
        return self._local_session

    def fetch_token(
        self, username: str, password: str, otp_code: Optional[str] = None
    ) -> Dict[str, Any]:
        return self._run_async_on_event_loop(
            self.async_fetch_token(username, password, otp_code)
        )

    async def async_fetch_token(
        self, username: str, password: str, otp_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """Initial token fetch with username/password & 2FA
        :type username: str
        :type password: str
        :type otp_code: str
        """
        headers = {"User-Agent": self.user_agent, "hardware_id": self.hardware_id}

        if otp_code:
            headers["2fa-support"] = "true"
            headers["2fa-code"] = otp_code

        try:
            body = self._oauth_client.prepare_request_body(
                username, password, scope=OAuth.SCOPE
            )
            data = dict(urldecode(body))
            resp = await self._session.request(
                "POST",
                OAuth.ENDPOINT,
                data=data,
                headers=headers,
                auth=self._auth,
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

    def refresh_tokens(self) -> Dict[str, Any]:
        return self._run_async_on_event_loop(self.async_refresh_tokens())

    async def async_refresh_tokens(self) -> Dict[str, Any]:
        """Refreshes the auth tokens"""
        try:
            headers = {
                "Accept": "application/json",
                "Content-Type": ("application/x-www-form-urlencoded;charset=UTF-8"),
            }
            body = self._oauth_client.prepare_refresh_body(
                refresh_token=self._token["refresh_token"]
            )
            data = dict(urldecode(body))
            resp = await self._session.request(
                "POST", OAuth.ENDPOINT, data=data, headers=headers, auth=self._auth
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

    def _start_background_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        asyncio.set_event_loop(loop)
        loop.run_forever()

    def _get_query_loop(
        self, current_loop: Optional[asyncio.AbstractEventLoop]
    ) -> asyncio.AbstractEventLoop:
        if current_loop is None:
            if self._init_loop:  # Running in executor
                return self._init_loop

            if not self._new_loop:
                self._new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._new_loop)
            return self._new_loop

        if not current_loop.is_running():
            return current_loop

        if self._background_thread_loop is None:
            self._background_thread_loop = asyncio.new_event_loop()
            t = Thread(
                target=self._start_background_loop,
                args=(self._background_thread_loop,),
                daemon=True,
                name="ring_doorbell_query_loop",
            )
            t.start()
        return self._background_thread_loop

    def _run_async_on_event_loop(self, func: Coroutine) -> Any:
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None
        loop = self._get_query_loop(current_loop)
        if self._loop and self._loop != loop:
            func.close()  # Close to prevent never awaited warnings
            raise RingError(
                "Detected event loop change, don't mix sync and async calls."
            )
        self._loop = loop
        # Running in an executor and loop is running or loop is on background thread
        if (
            current_loop is None and self._init_loop and self._loop.is_running()
        ) or loop == self._background_thread_loop:
            task = asyncio.run_coroutine_threadsafe(func, loop)
            return task.result()
        else:
            return loop.run_until_complete(func)

    async def async_close(self) -> None:
        """Close aiohttp session."""
        session = self._local_session
        self._local_session = None
        if session:
            await session.close()

    def close(self) -> None:
        """Close aiohttp session."""
        self._run_async_on_event_loop(self.async_close())

    def query(
        self,
        url: str,
        method: str = "GET",
        extra_params: Optional[Dict[str, Any]] = None,
        data: Optional[bytes] = None,
        json: Optional[Dict[Any, Any]] = None,
        timeout: Optional[float] = None,
        raise_for_status: bool = True,
    ) -> Response:
        return self._run_async_on_event_loop(
            self.async_query(
                url, method, extra_params, data, json, timeout, raise_for_status
            )
        )

    class Response:
        def __init__(self, content: bytes, status_code: int) -> None:
            self.content = content
            self.status_code = status_code

        @property
        def text(self) -> str:
            return self.content.decode()

        def json(self) -> Any:
            return json_loads(self.text)

    async def async_query(
        self,
        url: str,
        method: str = "GET",
        extra_params: Optional[Dict[str, Any]] = None,
        data: Optional[bytes] = None,
        json: Optional[Dict[Any, Any]] = None,
        timeout: Optional[float] = None,
        raise_for_status: bool = True,
    ) -> "Auth.Response":
        """Query data from Ring API."""
        if timeout is None:
            timeout = TIMEOUT

        params = {}
        if extra_params:
            params.update(extra_params)
        kwargs: Dict[str, Any] = {
            "params": params,
            "timeout": timeout,
        }
        headers = {"User-Agent": self.user_agent}
        if json is not None:
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
        except AuthenticationError as ex:
            raise ex  # refresh_tokens will return this error if not valid
        except Timeout as ex:
            raise RingTimeout(f"Timeout error during query of url {url}: {ex}") from ex
        except Exception as ex:
            raise RingError(f"Unknown error during query of url {url}: {ex}") from ex

        async with resp:
            if resp.status == 401:
                # Check whether there's an issue with the token grant
                self._token = await self.async_refresh_tokens()

            if raise_for_status:
                try:
                    resp.raise_for_status()
                except HTTPError as ex:
                    raise RingError(
                        f"HTTP error with status code {resp.status} "
                        + f"during query of url {url}: {ex}"
                    ) from ex

            response_data = await resp.read()
            auth_resp = Auth.Response(response_data, resp.status)
        return auth_resp
