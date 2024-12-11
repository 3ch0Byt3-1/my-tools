import socket
import threading
import requests
from tkinter import *
from tkinter import ttk
from scapy.all import IP, ICMP, sr1
from queue import Queue
from datetime import datetime
import json
queue = Queue()
open_ports = []
vulnerabilities = []
traceroute_results = []
print_lock = threading.Lock()

# Port Scanning
def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                banner = get_banner(target, port)
                with print_lock:
                    open_ports.append({"port": port, "service": banner})
                    update_results(f"Port {port} is open: {banner}")
                if banner:
                    check_vulnerabilities(banner)
    except Exception as e:
        pass

def get_banner(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((target, port))
            return s.recv(1024).decode().strip()
    except:
        return "Unknown service"

def check_vulnerabilities(service):
    try:
        response = requests.get(f"https://vulners.com/api/v3/search/lucene/",
                                params={"query": service, "limit": 5})
        if response.status_code == 200:
            vulns = response.json().get("data", {}).get("search", [])
            for vuln in vulns:
                vuln_info = f"{vuln['id']} - {vuln['description']}"
                vulnerabilities.append(vuln_info)
                update_results(f"Vulnerability: {vuln_info}")
    except Exception as e:
        update_results(f"Error fetching vulnerabilities for {service}")

def worker(target):
    while not queue.empty():
        port = queue.get()
        scan_port(target, port)
        queue.task_done()

# Traceroute
def perform_traceroute(target):
    global traceroute_results
    update_results(f"Starting traceroute to {target}")
    for ttl in range(1, 30):
        packet = IP(dst=target, ttl=ttl) / ICMP()
        reply = sr1(packet, timeout=2, verbose=0)
        if reply:
            traceroute_results.append(f"TTL {ttl}: {reply.src}")
            update_results(f"TTL {ttl}: {reply.src}")
            if reply.src == target:
                break
        else:
            traceroute_results.append(f"TTL {ttl}: Request timed out")
            update_results(f"TTL {ttl}: Request timed out")

# Results Update
def update_results(text):
    results_text.insert(END, f"{text}\n")
    results_text.see(END)

# GUI Functions
def start_scan():
    target = target_entry.get()
    start_port = int(start_port_entry.get())
    end_port = int(end_port_entry.get())
    num_threads = int(threads_entry.get())

    update_results(f"Scanning {target} from port {start_port} to {end_port}...")
    for port in range(start_port, end_port + 1):
        queue.put(port)

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(target,))
        t.start()
        threads.append(t)

    queue.join()
    update_results("Scan complete!")

def start_traceroute():
    target = target_entry.get()
    perform_traceroute(target)
    update_results("Traceroute complete!")

def save_results():
    results = {
        "open_ports": open_ports,
        "vulnerabilities": vulnerabilities,
        "traceroute": traceroute_results
    }
    with open(f"scan_results_{target_entry.get()}.json", "w") as f:
        json.dump(results, f, indent=4)
    update_results("Results saved to file!")

# GUI Setup
root = Tk()
root.title("Advanced Network Scanner")
root.geometry("800x600")

frame = Frame(root)
frame.pack(pady=10)

Label(frame, text="Target: ").grid(row=0, column=0, padx=5, pady=5)
target_entry = Entry(frame, width=20)
target_entry.grid(row=0, column=1, padx=5, pady=5)

Label(frame, text="Start Port: ").grid(row=1, column=0, padx=5, pady=5)
start_port_entry = Entry(frame, width=10)
start_port_entry.grid(row=1, column=1, padx=5, pady=5)

Label(frame, text="End Port: ").grid(row=2, column=0, padx=5, pady=5)
end_port_entry = Entry(frame, width=10)
end_port_entry.grid(row=2, column=1, padx=5, pady=5)

Label(frame, text="Threads: ").grid(row=3, column=0, padx=5, pady=5)
threads_entry = Entry(frame, width=10)
threads_entry.grid(row=3, column=1, padx=5, pady=5)

Button(frame, text="Start Scan", command=start_scan).grid(row=4, column=0, padx=5, pady=5)
Button(frame, text="Traceroute", command=start_traceroute).grid(row=4, column=1, padx=5, pady=5)
Button(frame, text="Save Results", command=save_results).grid(row=5, column=0, columnspan=2, pady=10)

results_text = Text(root, height=20, width=100)
results_text.pack(pady=10)

root.mainloop()
