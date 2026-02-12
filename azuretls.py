import base64
import ctypes
import json
import os
import platform
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, NotRequired, Optional, TypedDict


class KeyShare(TypedDict):
    group: int
    data: NotRequired[bytes]


class TlsSpecificationsInput(TypedDict):
    alpn_protocols: NotRequired[List[str]]
    signature_algorithms: NotRequired[List[int]]
    key_shares: NotRequired[List[KeyShare]]
    supported_versions: NotRequired[List[int]]
    cert_compression_algos: NotRequired[List[int]]
    delegated_credentials_algorithm_signatures: NotRequired[List[int]]
    psk_key_exchange_modes: NotRequired[List[int]]
    signature_algorithms_cert: NotRequired[List[int]]
    application_settings_protocols: NotRequired[List[str]]
    renegotiation_support: NotRequired[int]
    record_size_limit: NotRequired[int]
    permute_extensions: NotRequired[bool]


class AzureTLSResponse:
    """Wrapper for AzureTLS response"""

    def __init__(self, c_response):
        self.status_code = c_response.contents.status_code
        self.text: str = ""
        self.content: bytes = b""
        self.headers = None
        self.url = None
        self.error = None
        self.protocol = None

        if c_response.contents.body:
            self.content = ctypes.string_at(
                c_response.contents.body, c_response.contents.body_len
            )
            try:
                self.text = self.content.decode("utf-8")
            except UnicodeDecodeError:
                pass

        if c_response.contents.headers:
            headers_str = ctypes.string_at(c_response.contents.headers).decode("utf-8")
            self.headers = json.loads(headers_str) if headers_str else {}

        if c_response.contents.url:
            self.url = ctypes.string_at(c_response.contents.url).decode("utf-8")

        if c_response.contents.error:
            self.error = ctypes.string_at(c_response.contents.error).decode("utf-8")

        if c_response.contents.protocol:
            self.protocol = ctypes.string_at(c_response.contents.protocol).decode(
                "utf-8"
            )

    def json(self):
        assert self.content
        return json.loads(self.content)


class CFfiResponse(ctypes.Structure):
    """C structure for response"""

    _fields_ = [
        ("status_code", ctypes.c_int),
        ("body", ctypes.c_void_p),
        ("body_len", ctypes.c_int),
        ("headers", ctypes.c_char_p),
        ("url", ctypes.c_char_p),
        ("error", ctypes.c_char_p),
        ("protocol", ctypes.c_char_p),
    ]


def _load_library():
    """Load the appropriate shared library for the current platform"""
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Map Python architecture names to Go architecture names
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "i386": "386",
        "i686": "386",
        "arm64": "arm64",
        "aarch64": "arm64",
        "armv7l": "arm",
    }

    arch = arch_map.get(machine, machine)

    # Determine library extension
    if system == "windows":
        ext = ".dll"
    elif system == "darwin":
        ext = ".dylib"
    else:
        ext = ".so"

    # Try to find the library
    lib_name = f"libazuretls_{system}_{arch}{ext}"

    # Search paths
    search_paths = [Path(__file__).parent / "azure_libraries" / lib_name]

    lib = None
    for path in search_paths:
        try:
            if path.exists():
                lib = ctypes.CDLL(str(path.absolute()))
                break
        except OSError:
            continue

    if lib is None:
        raise RuntimeError(f"Could not load AzureTLS library. Tried: {search_paths}")

    return lib


def _setup_function_signatures():
    # azuretls_session_new
    azure_lib.azuretls_session_new.argtypes = [ctypes.c_char_p]
    azure_lib.azuretls_session_new.restype = ctypes.c_ulong

    # azuretls_session_close
    azure_lib.azuretls_session_close.argtypes = [ctypes.c_ulong]
    azure_lib.azuretls_session_close.restype = None

    # azuretls_session_do
    azure_lib.azuretls_session_do.argtypes = [ctypes.c_ulong, ctypes.c_char_p]
    azure_lib.azuretls_session_do.restype = ctypes.POINTER(CFfiResponse)

    # azuretls_session_apply_ja3
    azure_lib.azuretls_session_apply_ja3.argtypes = [
        ctypes.c_ulong,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    azure_lib.azuretls_session_apply_ja3.restype = ctypes.c_void_p

    # azuretls_session_apply_http2
    azure_lib.azuretls_session_apply_http2.argtypes = [
        ctypes.c_ulong,
        ctypes.c_char_p,
    ]
    azure_lib.azuretls_session_apply_http2.restype = ctypes.c_void_p

    # azuretls_session_apply_http3
    azure_lib.azuretls_session_apply_http3.argtypes = [
        ctypes.c_ulong,
        ctypes.c_char_p,
    ]
    azure_lib.azuretls_session_apply_http3.restype = ctypes.c_void_p

    # azuretls_session_set_proxy
    azure_lib.azuretls_session_set_proxy.argtypes = [ctypes.c_ulong, ctypes.c_char_p]
    azure_lib.azuretls_session_set_proxy.restype = ctypes.c_void_p

    # azuretls_session_clear_proxy
    azure_lib.azuretls_session_clear_proxy.argtypes = [ctypes.c_ulong]
    azure_lib.azuretls_session_clear_proxy.restype = None

    # azuretls_session_add_pins
    azure_lib.azuretls_session_add_pins.argtypes = [
        ctypes.c_ulong,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]
    azure_lib.azuretls_session_add_pins.restype = ctypes.c_void_p

    # azuretls_session_clear_pins
    azure_lib.azuretls_session_clear_pins.argtypes = [
        ctypes.c_ulong,
        ctypes.c_char_p,
    ]
    azure_lib.azuretls_session_clear_pins.restype = ctypes.c_void_p

    # azuretls_session_get_ip
    azure_lib.azuretls_session_get_ip.argtypes = [ctypes.c_ulong]
    azure_lib.azuretls_session_get_ip.restype = ctypes.c_void_p

    # azuretls_session_get_cookies
    azure_lib.azuretls_session_get_cookies.argtypes = [
        ctypes.c_ulong,
        ctypes.c_char_p,
    ]
    azure_lib.azuretls_session_get_cookies.restype = ctypes.c_void_p

    azure_lib.azuretls_session_new_websocket.argtypes = [
        ctypes.c_ulong,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    azure_lib.azuretls_session_new_websocket.restype = ctypes.c_void_p
    azure_lib.azuretls_websocket_close.argtypes = [ctypes.c_ulong]

    azure_lib.azuretls_websocket_read_message.argtypes = [
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.POINTER(ctypes.c_ulong),
    ]
    azure_lib.azuretls_websocket_read_message.restype = ctypes.c_void_p

    azure_lib.azuretls_websocket_write_message.argtypes = [
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_char_p,
        ctypes.c_ulong,
    ]
    azure_lib.azuretls_websocket_write_message.restype = ctypes.c_char_p

    # azuretls_free_string
    azure_lib.azuretls_free_string.argtypes = [ctypes.c_void_p]
    azure_lib.azuretls_free_string.restype = None

    # azuretls_free_response
    azure_lib.azuretls_free_response.argtypes = [ctypes.POINTER(CFfiResponse)]
    azure_lib.azuretls_free_response.restype = None

    # azuretls_version
    azure_lib.azuretls_version.argtypes = []
    azure_lib.azuretls_version.restype = ctypes.c_void_p

    # azuretls_init
    azure_lib.azuretls_init.argtypes = []
    azure_lib.azuretls_init.restype = None

    # azuretls_cleanup
    azure_lib.azuretls_cleanup.argtypes = []
    azure_lib.azuretls_cleanup.restype = None


azure_lib = _load_library()
_setup_function_signatures()
azure_lib.azuretls_init()


class AzureTLSSession:
    """Python wrapper for AzureTLS session"""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        *,
        session_id: Optional[int] = None,
    ):
        if session_id is not None:
            self.session_id = session_id
            return
        config_json = json.dumps(config).encode("utf-8") if config else None
        self.session_id = azure_lib.azuretls_session_new(config_json)
        if self.session_id == 0:
            raise RuntimeError("Failed to create AzureTLS session")

    def do(
        self,
        method: str,
        url: str,
        query: Optional[dict[str, Any]] = None,
        body: Optional[str | bytes] = None,
        form: Optional[dict] = None,
        headers: Optional[Dict[str, str | list[str]]] = None,
        timeout_ms: Optional[int] = None,
        force_http1: bool = False,
        force_http3: bool = False,
        ignore_body: bool = False,
        dont_send_cookies: bool = False,
        dont_write_cookies: bool = False,
        disable_redirects: bool = False,
        max_redirects: Optional[int] = None,
        insecure_skip_verify: bool = True,
    ) -> AzureTLSResponse:
        """Make an HTTP request"""
        if form is not None:
            body = urllib.parse.urlencode(form)
        if query is not None:
            url = f"{url}?{urllib.parse.urlencode(query)}"

        request_data: dict[str, Any] = {
            "method": method,
            "url": url,
        }

        if body is not None:
            if isinstance(body, str):
                request_data["body"] = body
            else:
                request_data["body_b64"] = base64.b64encode(body)

        if headers is not None:
            request_data["headers"] = {"Header-Order:": []}
            for k, v in headers.items():
                request_data["headers"]["Header-Order:"].append(k.lower())
                if isinstance(v, list):
                    request_data["headers"][k] = v
                elif isinstance(v, str):
                    request_data["headers"][k] = [v]
        if timeout_ms is not None:
            request_data["timeout_ms"] = timeout_ms
        request_data["force_http1"] = force_http1
        request_data["force_http3"] = force_http3
        request_data["ignore_body"] = ignore_body
        request_data["dont_send_cookies"] = dont_send_cookies
        request_data["dont_write_cookies"] = dont_write_cookies
        if disable_redirects:
            request_data["disable_redirects"] = True
        if max_redirects is not None:
            request_data["max_redirects"] = max_redirects
        if insecure_skip_verify:
            request_data["insecure_skip_verify"] = True

        request_json = json.dumps(request_data).encode("utf-8")
        c_response = azure_lib.azuretls_session_do(self.session_id, request_json)
        if not c_response:
            raise RuntimeError("Failed to execute request")

        try:
            response = AzureTLSResponse(c_response)
            if response.error:
                raise RuntimeError(response.error)
            return response
        finally:
            azure_lib.azuretls_free_response(c_response)

    def get(self, url: str, **kwargs) -> AzureTLSResponse:
        """Make a GET request"""
        return self.do("GET", url, **kwargs)

    def post(self, url: str, body: Optional[str] = None, **kwargs) -> AzureTLSResponse:
        """Make a POST request"""
        return self.do("POST", url, body=body, **kwargs)

    def put(self, url: str, body: Optional[str] = None, **kwargs) -> AzureTLSResponse:
        """Make a PUT request"""
        return self.do("PUT", url, body=body, **kwargs)

    def delete(self, url: str, **kwargs) -> AzureTLSResponse:
        """Make a DELETE request"""
        return self.do("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs) -> AzureTLSResponse:
        """Make a HEAD request"""
        return self.do("HEAD", url, ignore_body=True, **kwargs)

    def options(self, url: str, **kwargs) -> AzureTLSResponse:
        """Make an OPTIONS request"""
        return self.do("OPTIONS", url, **kwargs)

    def patch(self, url: str, body: Optional[str] = None, **kwargs) -> AzureTLSResponse:
        """Make a PATCH request"""
        return self.do("PATCH", url, body=body, **kwargs)

    def apply_ja3(
        self,
        ja3: str,
        navigator: str = "chrome",
        tls_specifications: Optional[TlsSpecificationsInput] = None,
    ) -> None:
        """Apply JA3 fingerprint"""
        ja3_bytes = ja3.encode("utf-8")
        navigator_bytes = navigator.encode("utf-8")

        tls_specifications_encode = None

        if tls_specifications is not None:
            tls_specifications_encode = json.dumps(tls_specifications).encode("utf-8")

        error = azure_lib.azuretls_session_apply_ja3(
            self.session_id, ja3_bytes, navigator_bytes, tls_specifications_encode
        )
        if error:
            error_str = ctypes.string_at(error).decode("utf-8")
            azure_lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to apply JA3: {error_str}")

    def apply_http2(self, fingerprint: str) -> None:
        """Apply HTTP/2 fingerprint"""
        fp_bytes = fingerprint.encode("utf-8")

        error = azure_lib.azuretls_session_apply_http2(self.session_id, fp_bytes)
        if error:
            error_str = ctypes.string_at(error).decode("utf-8")
            azure_lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to apply HTTP/2 fingerprint: {error_str}")

    def apply_http3(self, fingerprint: str) -> None:
        """Apply HTTP/3 fingerprint"""
        fp_bytes = fingerprint.encode("utf-8")

        error = azure_lib.azuretls_session_apply_http3(self.session_id, fp_bytes)
        if error:
            error_str = ctypes.string_at(error).decode("utf-8")
            azure_lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to apply HTTP/3 fingerprint: {error_str}")

    def set_proxy(self, proxy: str) -> None:
        """Set proxy for the session"""
        proxy_bytes = proxy.encode("utf-8")

        error = azure_lib.azuretls_session_set_proxy(self.session_id, proxy_bytes)
        if error:
            error_str = ctypes.string_at(error).decode("utf-8")
            azure_lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to set proxy: {error_str}")

    def clear_proxy(self) -> None:
        """Clear proxy from the session"""
        azure_lib.azuretls_session_clear_proxy(self.session_id)

    def add_pins(self, url: str, pins: List[str]) -> None:
        """Add SSL pins for a URL"""
        url_bytes = url.encode("utf-8")
        pins_json = json.dumps(pins).encode("utf-8")

        error = azure_lib.azuretls_session_add_pins(
            self.session_id, url_bytes, pins_json
        )
        if error:
            error_str = ctypes.string_at(error).decode("utf-8")
            azure_lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to add pins: {error_str}")

    def clear_pins(self, url: str) -> None:
        """Clear SSL pins for a URL"""
        url_bytes = url.encode("utf-8")

        error = azure_lib.azuretls_session_clear_pins(self.session_id, url_bytes)
        if error:
            error_str = ctypes.string_at(error).decode("utf-8")
            azure_lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to clear pins: {error_str}")

    def get_ip(self) -> str:
        """Get the public IP address"""
        result = azure_lib.azuretls_session_get_ip(self.session_id)
        if result:
            ip = ctypes.string_at(result).decode("utf-8")
            azure_lib.azuretls_free_string(result)
            if ip.startswith("error:"):
                raise RuntimeError(ip)
            return ip
        raise RuntimeError("Failed to get IP address")

    def get_cookies(self, url: str) -> List[Dict[str, Any]]:
        """Get cookies for a specific URL"""
        url_bytes = url.encode("utf-8")
        result = azure_lib.azuretls_session_get_cookies(self.session_id, url_bytes)
        if result:
            cookies_str = ctypes.string_at(result).decode("utf-8")
            azure_lib.azuretls_free_string(result)
            if cookies_str.startswith("error:"):
                raise RuntimeError(cookies_str)
            return json.loads(cookies_str)
        raise RuntimeError("Failed to get cookies")

    def get_version(self) -> str:
        """Get library version"""
        result = azure_lib.azuretls_version()
        if result:
            version = ctypes.string_at(result).decode("utf-8")
            azure_lib.azuretls_free_string(result)
            return version
        return "unknown"

    def close(self):
        """Close the session and free resources"""
        print("close called")
        if hasattr(self, "session_id") and self.session_id != 0:
            azure_lib.azuretls_session_close(self.session_id)
            self.session_id = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class AzureTLSWebsocket:
    def __init__(
        self,
        sessionID: int,
        url: str,
        headers: Optional[dict[str, str | list[str]]] = None,
        enable_compression: bool = False,
        subprotocols: Optional[list[str]] = None,
        read_buffer_size: int = 0,
        write_buffer_size: int = 0,
    ) -> None:
        self.session_id = sessionID
        headers = headers if headers else {}
        config = {
            "url": url,
            "read_buffer_size": read_buffer_size,
            "write_buffer_size": write_buffer_size,
            "subprotocols": subprotocols,
            "enable_compression": enable_compression,
            "headers": {"Header-Order:": []},
        }

        for k, v in headers.items():
            config["headers"]["Header-Order:"].append(k.lower())
            if isinstance(v, list):
                config["headers"][k] = v
            elif isinstance(v, str):
                config["headers"][k] = [v]
        ws_session_id = ctypes.c_size_t()

        error = azure_lib.azuretls_session_new_websocket(
            self.session_id, json.dumps(config).encode(), ctypes.byref(ws_session_id)
        )
        if error:
            error_str = ctypes.string_at(error).decode("utf-8")
            azure_lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to create websocket session: {error_str}")
        self.ws_session_id = ws_session_id.value

    def recv(self):
        message_typeC = ctypes.c_ulong()
        messageC = ctypes.c_char_p()
        message_lengthC = ctypes.c_ulong()
        error = azure_lib.azuretls_websocket_read_message(
            self.ws_session_id,
            ctypes.byref(message_typeC),
            ctypes.byref(messageC),
            ctypes.byref(message_lengthC),
        )
        if error:
            error_str = ctypes.string_at(error).decode("utf-8")
            azure_lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to receive websocket: {error_str}")
        return ctypes.string_at(messageC, message_lengthC.value), message_typeC.value

    def send(self, message: bytes, message_type: int):
        error = azure_lib.azuretls_websocket_write_message(
            self.ws_session_id, message_type, ctypes.c_char_p(message), len(message)
        )
        if error:
            error_str = ctypes.string_at(error).decode("utf-8")
            azure_lib.azuretls_free_string(error)
            raise RuntimeError(f"Failed to write websocket message: {error_str}")
