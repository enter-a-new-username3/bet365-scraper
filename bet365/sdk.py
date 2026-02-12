def build_cookies(cookies: dict[str, str]) -> str:
    result = ""
    for key, value in cookies.items():
        result += f"{key}={value}; "
    if len(result) > 0:
        result = result[:-2]
    return result
