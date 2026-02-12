import base64
import hashlib
import threading
import uuid
from typing import Union

from curl_cffi import Session

import sdk


class Bet365WebSession(Session):
    def __init__(self):
        raise NotImplementedError(
            "Web demo is available but It isn't implemented on Github yet."
        )
