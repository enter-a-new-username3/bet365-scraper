import base64
import hashlib
import threading
import uuid
from typing import Union

from curl_cffi.requests import Session, get

import sdk

TLS_FINGERPRINT = {
    "ja3": "771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0",
    "akamai": "4:16777216|16711681|0|m,p,a,s",
    "extra_fp": {
        "tls_signature_algorithms": [
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512",
            "rsa_pkcs1_sha1",
        ]
    },
}


class Bet365AndroidSession(Session):
    def __init__(
        self, api_url: str, api_key: str, *args, host="www.bet365.com", **kwargs
    ):
        kwargs.update(TLS_FINGERPRINT)
        super().__init__(*args, **kwargs)
        self.host = host
        self.api_url = api_url
        self.api_key = api_key
        self._cookie_lock = threading.Lock()
        self.device_id = str(uuid.uuid4())
        self._sst = ""

    def go_homepage(self):
        homepage_response = self.get(
            f"https://{self.host}/",
            headers={
                "x-b365app-id": "8.0.14.00-row",
                "sec-ch-ua": '"Android WebView";v="141", "Not?A_Brand";v="8", "Chromium";v="141"" Gen6 "',
                "sec-ch-ua-mobile": "?1",
                "sec-ch-ua-platform": '"Android"',
                "upgrade-insecure-requests": "1",
                "user-agent": "Mozilla (Linux; Android 12 Phone; CPU M2003J15SC OS 12 like Gecko) Chrome/141.0.7390.122 Gen6 bet365/8.0.14.00",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "x-requested-with": "com.bet365Wrapper.Bet365_Application",
                "sec-fetch-site": "none",
                "sec-fetch-mode": "navigate",
                "sec-fetch-user": "?1",
                "sec-fetch-dest": "document",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
                "referer": f"https://{self.host}",
            },
            default_headers=False,
        )
        assert homepage_response.status_code == 200, (
            "Blocked by Cloudflare, bad IP or headers should be updated"
            if homepage_response.status_code == 403
            else f"Unknown error while going to homepage: {homepage_response.status_code}"
        )
        configuration_response = self.get(
            f"https://{self.host}"
            + homepage_response.text.split('"SITE_CONFIG_LOCATION":"')[1].split('"')[0],
            headers={
                "origin": f"https://{self.host}",
                "sec-ch-ua-platform": '"Windows"',
                "user-agent": "Mozilla (Linux; Android 12 Phone; CPU M2003J15SC OS 12 like Gecko) Chrome/141.0.7390.122 Gen6 bet365/8.0.14.00",
                "sec-ch-ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Brave";v="140"',
                "sec-ch-ua-mobile": "?0",
                "accept": "*/*",
                "sec-gpc": "1",
                "accept-language": "tr-TR,tr;q=0.5",
                "sec-fetch-site": "same-origin",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty",
                "referer": f"https://{self.host}/",
                "accept-encoding": "gzip, deflate, br, zstd",
                "priority": "u=1, i",
            },
            default_headers=False,
        )
        assert configuration_response.status_code == 200, (
            "Blocked while getting configuration, probably bad IP"
            if configuration_response.status_code == 500
            else f"Unknown error while fetching configuration: {configuration_response.status_code}"
        )

        self._sst = configuration_response.json()["ns_weblib_util"]["WebsiteConfig"][
            "SST"
        ]

    def protected_get(
        self, url: str, headers: Union[dict[str, str], None] = None, *args, **kwargs
    ):
        headers = headers or {}

        host_cookies = {}
        dot_host_cookies = {}
        for cookie in self.cookies.jar:
            if cookie.domain == self.host:
                host_cookies[cookie.name] = cookie.value
            else:
                dot_host_cookies[cookie.name] = cookie.value

        host_cookies.update(dot_host_cookies)

        cookie_header = sdk.build_cookies(host_cookies)
        headers["X-Net-Sync-Term-Android"] = self.get_x_net_header(
            url, cookie_header, b""
        )
        headers["Cookie"] = cookie_header
        kwargs["default_headers"] = False
        kwargs.update(TLS_FINGERPRINT)
        response = get(url, headers=headers, *args, **kwargs)

        return response

    def get_x_net_header(self, url: str, cookie_header: str, post_data: bytes) -> str:
        response = Session().post(
            self.api_url,
            headers={"x-net-api-key": self.api_key},
            json={
                "url": url,
                "cookie": cookie_header,
                "post_hash": base64.b64encode(
                    hashlib.sha256(post_data).digest()
                ).decode(),
                "sst": self._sst,
                "device_id": self.device_id,
            },
        )
        assert response.status_code == 200, (
            "An error occured while generating token: " + response.text
        )
        return response.text
