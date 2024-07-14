import asyncio
import aiohttp
import json
import logging
import json
import re
import time
import secrets
import urllib
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List
from urllib import parse
from urllib.parse import quote

import aiohttp
from aiohttp import ClientResponse
from yarl import URL

from pyhon import const, exceptions
from pyhon.connection.device import HonDevice
from pyhon.connection.handler.auth import HonAuthConnectionHandler

_LOGGER = logging.getLogger(__name__)


@dataclass
class HonLoginData:
    url: str = ""
    email: str = ""
    password: str = ""
    fw_uid: str = ""
    loaded: Optional[Dict[str, Any]] = None


@dataclass
class HonAuthData:
    access_token: str = ""
    cognito_token: str = ""
    id_token: str = ""


class HonAuth:
    _TOKEN_EXPIRES_AFTER_HOURS = 6
    _TOKEN_EXPIRE_WARNING_HOURS = 5

    def __init__(
        self,
        session: aiohttp.ClientSession,
        email: str,
        password: str,
        device: HonDevice,
    ) -> None:
        self._session = session
        self._request = HonAuthConnectionHandler(session)
        self._login_data = HonLoginData()
        self._login_data.email = email
        self._login_data.password = password
        self._device = device
        self._expires: datetime = datetime.utcnow()
        self._auth = HonAuthData()
        self._frontdoor_url = ""
        self._start_time    = time.time()
        self._mobile_id = secrets.token_hex(8)

        self._framework = "framework"
        self._header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36"
        }
        self._session = aiohttp.ClientSession(headers=self._header)

    @property
    def cognito_token(self) -> str:
        return self._auth.cognito_token

    @property
    def id_token(self) -> str:
        return self._auth.id_token

    @property
    def access_token(self) -> str:
        return self._auth.access_token

    def _check_token_expiration(self, hours: int) -> bool:
        return datetime.utcnow() >= self._expires + timedelta(hours=hours)

    @property
    def token_is_expired(self) -> bool:
        return self._check_token_expiration(self._TOKEN_EXPIRES_AFTER_HOURS)

    @property
    def token_expires_soon(self) -> bool:
        return self._check_token_expiration(self._TOKEN_EXPIRE_WARNING_HOURS)

    async def _error_logger(self, response: ClientResponse, fail: bool = True) -> None:
        output = "hOn Authentication Error\n"
        for i, (status, url) in enumerate(self._request.called_urls):
            output += f" {i + 1: 2d}     {status} - {url}\n"
        output += f"ERROR - {response.status} - {response.request_info.url}\n"
        output += f"{15 * '='} Response {15 * '='}\n{await response.text()}\n{40 * '='}"
        _LOGGER.error(output)
        if fail:
            raise exceptions.HonAuthenticationError("Can't login")

    @staticmethod
    def _generate_nonce() -> str:
        nonce = secrets.token_hex(16)
        return f"{nonce[:8]}-{nonce[8:12]}-{nonce[12:16]}-{nonce[16:20]}-{nonce[20:]}"

    async def authenticate(self) -> None:
        self.clear()
        try:
            if not await self._authenticate():
                raise exceptions.HonAuthenticationError("Could not authenticate")
        except exceptions.HonNoAuthenticationNeeded:
            return

    async def _authenticate(self) -> bool:
        if await self._async_get_frontdoor_url(0) == 1:
            return False

        async with self._session.get(self._frontdoor_url) as resp:
            if resp.status != 200:
                _LOGGER.error("Unable to connect to the login service: " + str(resp.status))
                return False
            await resp.text()

        url = f"{const.AUTH_API2}/apex/ProgressiveLogin?retURL=%2FSmartHome%2Fapex%2FCustomCommunitiesLanding"
        async with self._session.get(url) as resp:
            await resp.text()
            
        url = f"{const.AUTH_API2}/services/oauth2/authorize?response_type=token+id_token&client_id=3MVG9QDx8IX8nP5T2Ha8ofvlmjLZl5L_gvfbT9.HJvpHGKoAS_dcMN8LYpTSYeVFCraUnV.2Ag1Ki7m4znVO6&redirect_uri=hon%3A%2F%2Fmobilesdk%2Fdetect%2Foauth%2Fdone&display=touch&scope=api%20openid%20refresh_token%20web&nonce=82e9f4d1-140e-4872-9fad-15e25fbf2b7c"
        async with self._session.get(url) as resp:
            text = await resp.text()
            array = []
            try:
                array = text.split("'", 2)

                if( len(array) == 1 ):
                    #Implement a second way to get the token value
                    m = re.search('id_token\=(.+?)&', text)
                    if m:
                        self._auth.id_token = m.group(1)
                    else:
                        _LOGGER.error("Unable to get [id_token] during authorization process (tried both options). Full response [" + text + "]")
                        return False
                else:
                    params = urllib.parse.parse_qs(array[1])
                    self._auth.id_token = params["id_token"][0]
            except:
                _LOGGER.error("Unable to get [id_token] during authorization process. Full response [" + text + "]")
                return False

        post_headers = {"id-token": self._auth.id_token}
        data = {"appVersion": const.APP_VERSION,
                "mobileId": self._mobile_id,
                "os": const.OS,
                "osVersion": const.OS_VERSION,
                "deviceModel": const.DEVICE_MODEL}

        async with self._session.post(f"{const.API_URL}/auth/v1/login", headers=post_headers, json=data) as resp:
            try:
                json_data = await resp.json()
                self._auth.cognito_token = json_data["cognitoUser"]["Token"]
            except:
                text = await resp.text()
                _LOGGER.error("hOn Invalid Data ["+ str(resp.text()) + "] after sending command ["+ str(data)+ "] with headers [" + str(post_headers) + "]. Response: " + text)
                return False
    
        self._start_time = time.time()
        return True
    
        return True

    async def _async_get_frontdoor_url(self, error_code=0):

        data = (
            "message=%7B%22actions%22%3A%5B%7B%22id%22%3A%2279%3Ba%22%2C%22descriptor%22%3A%22apex%3A%2F%2FLightningLoginCustomController%2FACTION%24login%22%2C%22callingDescriptor%22%3A%22markup%3A%2F%2Fc%3AloginForm%22%2C%22params%22%3A%7B%22username%22%3A%22"
            + urllib.parse.quote(self._login_data.email)
            + "%22%2C%22password%22%3A%22"
            + urllib.parse.quote(self._login_data.password)
            + "%22%2C%22startUrl%22%3A%22%22%7D%7D%5D%7D&aura.context=%7B%22mode%22%3A%22PROD%22%2C%22fwuid%22%3A%22"
            + urllib.parse.quote(self._framework)
            + "%22%2C%22app%22%3A%22siteforce%3AloginApp2%22%2C%22loaded%22%3A%7B%22APPLICATION%40markup%3A%2F%2Fsiteforce%3AloginApp2%22%3A%22YtNc5oyHTOvavSB9Q4rtag%22%7D%2C%22dn%22%3A%5B%5D%2C%22globals%22%3A%7B%7D%2C%22uad%22%3Afalse%7D&aura.pageURI=%2FSmartHome%2Fs%2Flogin%2F%3Flanguage%3Dfr&aura.token=null"
        )

        async with self._session.post(
            f"{const.AUTH_API2}/s/sfsites/aura?r=3&other.LightningLoginCustom.login=1",
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
            data=data,
        ) as resp:
            if resp.status != 200:
                _LOGGER.error("Unable to connect to the login service: " + str(resp.status))
                return False

            text = await resp.text()
            try:
                json_data = json.loads(text)
                self._frontdoor_url = json_data["events"][0]["attributes"]["values"]["url"]
            except:
                # Framework must be updated
                if text.find("clientOutOfSync") > 0 and error_code != 2:
                    start = text.find("Expected: ") + 10
                    end = text.find(" ", start)
                    _LOGGER.debug("Framework update from ["+ self._framework+ "] to ["+ text[start:end]+ "]")
                    self._framework = text[start:end]
                    return await self._async_get_frontdoor_url(2)
                _LOGGER.error("Unable to retreive the frontdoor URL. Message: " + text)
                return 1

        if error_code == 2 and self._entry != None:
            # Update Framework
            data = {**self._entry.data}
            data["framework"] = self._framework
            self._hass.config_entries.async_update_entry(self._entry, data=data)

        return 0
    

    async def refresh(self) -> bool:
        self._session.cookie_jar.clear()
        return await self._authenticate()

    def clear(self) -> None:
        self._session.cookie_jar.clear_domain(const.AUTH_API.split("/")[-2])
        self._request.called_urls = []
        self._auth.cognito_token = ""
        self._auth.id_token = ""
        self._auth.access_token = ""
