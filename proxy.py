import requests

proxies = {
    "http": "http://rb-proxy-in.bosch.com:8080",
    "https": "http://rb-proxy-in.bosch.com:8080"
}

try:
    r = requests.get("https://www.google.com", proxies=proxies)
    print(r.status_code)
except Exception as e:
    print(f"Proxy test failed: {e}")