import requests

proxies = {
        'http': f"socks5://localhost:1080",
        'https': f"socks5://localhost:1080"
}
response = requests.get("http://www.google.com", proxies=proxies, timeout=10)
print(response.status_code)