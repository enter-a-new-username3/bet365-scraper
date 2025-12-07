import json
import re
from typing import TypedDict

from android import Bet365AndroidSession

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


r = s.protected_get(
    "https://www.bet365.com/splashcontentapi/getsplashpods?lid=32&zid=0&pd=%23AS%23B1%23&cid=198&cgid=3&ctid=198&csid=3&tzo=-300",
    headers={
        "User-Agent": "Mozilla (Linux; Android 12 Phone; CPU M2003J15SC OS 12 like Gecko) Chrome/141.0.7390.122 Gen6 bet365/8.0.14.00",
        "X-b365App-ID": "8.0.14.00-row",
        "Accept-Encoding": "gzip",
    },
    proxy=config["proxy"] or None,
    verify=False,
)

print("Matches:")

pattern = re.compile(r"NA=([^;]+);N2=([^;]+);")

for a, i in enumerate(pattern.finditer(r.text)):
    print(f"\t{i.group(1)} vs {i.group(2)}")
    if a == 10:
        print("\t...")
        break

with open("1.txt", "w", encoding="utf8") as fp:
    fp.write(r.text)
