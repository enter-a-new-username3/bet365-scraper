import json
import re
from typing import TypedDict

from android import Bet365AndroidSession
from message_parser import Bet365MessageParser, get_parsers, read_table

with open("config.json", encoding="utf8") as fp:
    config = json.load(fp)

print("Fetching soccer page using android api")

s = Bet365AndroidSession(
    config["api_url"],
    config["api_key"],
    proxy=config["proxy"] or None,
    verify=False,
    host="www.bet365.com",
)
s.go_homepage()

sports = s.extract_available_sports()
soccer = next(filter(lambda m: m.name == "Soccer", sports))
s.get_sport_homepage(soccer)
