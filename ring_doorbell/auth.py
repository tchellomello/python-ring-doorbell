# vim:sw=4:ts=4:et:
"""Python Ring Auth Class."""
import uuid
from typing import Any, Callable, Dict, Optional

from oauthlib.common import urldecode
from oauthlib.oauth2 import (
    LegacyApplicationClient,
    MissingTokenError,
    OAuth2Error,
    TokenExpiredError,
)
from requests import HTTPError, Response, Session, Timeout
from requests import auth as requests_auth
from requests.adapters import HTTPAdapter, Retry

from ring_doorbell.const import API_URI, NAMESPACE_UUID, TIMEOUT, OAuth
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
        self._session = Session()
        self._oauth_client = LegacyApplicationClient(
            client_id=OAuth.CLIENT_ID, token=token
        )
        self._auth = requests_auth.HTTPBasicAuth(OAuth.CLIENT_ID, "")
        retries = Retry(connect=5, read=0, backoff_factor=2)
        self._session.mount(API_URI, HTTPAdapter(max_retries=retries))

    def fetch_token(
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
            resp = self._session.request(
                "POST",
                OAuth.ENDPOINT,
                data=data,
                headers=headers,
                auth=self._auth,
                verify=True,
            )
            self._token = self._oauth_client.parse_request_body_response(
                resp.text, scope=OAuth.SCOPE
            )
        except MissingTokenError as ex:
            raise Requires2FAError from ex
        except OAuth2Error as ex:
            raise AuthenticationError(ex) from ex

        if self.token_updater is not None:
            self.token_updater(self._token)

        return self._token

    def refresh_tokens(self) -> Dict[str, Any]:
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
            resp = self._session.request(
                "POST", OAuth.ENDPOINT, data=data, headers=headers, auth=self._auth
            )
            self._token = self._oauth_client.parse_request_body_response(
                resp.text, scope=OAuth.SCOPE
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
                resp = self._session.request(
                    method, url, headers=headers, data=data, **kwargs
                )
            except TokenExpiredError:
                self._token = self.refresh_tokens()
                url, headers, data = self._oauth_client.add_token(
                    url,
                    http_method=method,
                    body=data,
                    headers=headers,
                )
                resp = self._session.request(
                    method, url, headers=headers, data=data, **kwargs
                )
        except AuthenticationError as ex:
            raise ex  # refresh_tokens will return this error if not valid
        except Timeout as ex:
            raise RingTimeout(f"Timeout error during query of url {url}: {ex}") from ex
        except Exception as ex:
            raise RingError(f"Unknown error during query of url {url}: {ex}") from ex

        if resp.status_code == 401:
            # Check whether there's an issue with the token grant
            self._token = self.refresh_tokens()

        if raise_for_status:
            try:
                resp.raise_for_status()
            except HTTPError as ex:
                raise RingError(
                    f"HTTP error with status code {resp.status_code} "
                    + f"during query of url {url}: {ex}"
                ) from ex

        return resp
