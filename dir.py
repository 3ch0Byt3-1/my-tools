import requests

base_url = "https://bytecapsule.io"
#--------------------------------------------------------------------
paths = [
    "cgi-bin", "assets", "webmail", "controlpanel", "cpanel", "whm", 
    "~mike", "~jeff", "~masmith", "~rachna", "~greg"
]
#--------------------------------------------------------------------
for path in paths:
#--------------------------------------------------------------------
    url = f"{base_url}/{path}"
    try:
        response = requests.get(url, allow_redirects=False)
        print(f"Path: {url} | Status Code: {response.status_code}")
        if response.status_code == 200:
            print(f"Content Snippet: {response.text[:200]}\n")
        elif response.status_code in [301, 302]:
            print(f"Redirects To: {response.headers.get('Location')}\n")
#--------------------------------------------------------------------
    except requests.exceptions.RequestException as e:
        print(f"Error accessing {url}: {e}")
