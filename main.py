import json

from bet365 import Bet365AndroidSession

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
print("Going to homepage started taking longer than it should because of curl_cffi.")
s.go_homepage()

sports = s.extract_available_sports()
tennis = next(filter(lambda m: m.name == "Soccer", sports))
s.get_sport_homepage(tennis)
s.zap_thread.join()
