import requests
def get_real_ip(website):
    try:
        import socket
        ip_address = socket.gethostbyname(website)

        url = f"https://ipinfo.io/{ip_address}/json?token=3c9355c23d88d9"    
        response = requests.get(url)   
        if response.status_code == 200:
            data = response.json()
            if 'ip' in data:
                return data['ip']
            else:
                return "IP address not found"
        else:
            return f"Error: {response.status_code}"

    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
    except socket.gaierror:
        return "Error: Unable to resolve domain name"

website = input("Enter the website URL (e.g., bytecapsule.io): ")
ip = get_real_ip(website)
print(f"The IP address of {website} is: {ip}")
