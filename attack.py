import requests

url = "http://127.0.0.1:5000/login"

passwords = ["123456", "zishan", "admin", "zishan2", "letmein", "asasas", "sasasas", "sdsdsds"]

for p in passwords:
    r = requests.post(url, data={
        "username": "zishan",
        "password": p
    }, allow_redirects=True)

    if "Dashboard" in r.text:
        print(f"[SUCCESS] {p}")
    elif "locked" in r.text.lower():
        print(f"[LOCKED] {p}")
    elif r.status_code == 429:
        print(f"[RATE LIMITED] {p}")
    else:
        print(f"[FAILED] {p}")
