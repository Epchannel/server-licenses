# EP Channel License Server — Integration Guide

## SERVER
- Base URL: `http://your-server:8000` (thay bằng domain thực tế)
- Không cần auth token để verify/heartbeat

## API ENDPOINTS

### 1. VERIFY LICENSE
```
POST /api/v2/{TOOL_CODE}/verify
Content-Type: application/json

Body:
{
  "license_key": "string (required)",
  "device_id": "string (optional - auto bind first time)",
  "device_name": "string (optional)"
}

Response OK:
{ "valid": true, "expire_at": "ISO datetime", "message": "...", "user_name": "...", "signature": "..." }

Response FAIL:
{ "valid": false, "message": "Key bản quyền không hợp lệ | Bản quyền đã hết hạn | Key đã được gán cho thiết bị khác" }
```

### 2. HEARTBEAT (gửi mỗi 5 phút khi tool đang chạy)
```
POST /license/heartbeat
Content-Type: application/json

Body:
{ "license_key": "string (required)", "device_id": "string (required)" }

Response:
{ "valid": true/false, "message": "Heartbeat OK | ...", "timestamp": "...", "signature": "..." }
```

## TOOL_CODE LIST
Mỗi tool có 1 code riêng, endpoint: `/api/v2/{TOOL_CODE}/verify`
Ví dụ: `VER_PHONE_VEO`, `CHECK_VEO3`, `PICK_VEO3`, `CHANGE_PASS_VEO3`

## DEVICE_ID
Dùng MAC address hoặc hardware ID ổn định (không random):
```python
import uuid, socket
DEVICE_ID = f"{uuid.getnode()}-{socket.gethostname()}"
```

## PYTHON INTEGRATION (copy class này vào project)

```python
import requests, uuid, socket, threading, time, sys

class LicenseManager:
    def __init__(self, server_url, tool_code):
        self.server_url = server_url.rstrip("/")
        self.tool_code = tool_code
        self.device_id = f"{uuid.getnode()}-{socket.gethostname()}"
        self.license_key = None
        self.user_name = None
        self.expire_at = None

    def verify(self, license_key):
        self.license_key = license_key
        try:
            r = requests.post(f"{self.server_url}/api/v2/{self.tool_code}/verify",
                json={"license_key": license_key, "device_id": self.device_id, "device_name": socket.gethostname()}, timeout=10)
            d = r.json()
            if d.get("valid"):
                self.user_name = d.get("user_name")
                self.expire_at = d.get("expire_at")
                return True, d
            return False, d.get("message", "License không hợp lệ")
        except requests.exceptions.ConnectionError:
            return False, "Không kết nối được license server"
        except Exception as e:
            return False, str(e)

    def start_heartbeat(self, interval=300):
        if not self.license_key: return
        def loop():
            while True:
                try:
                    requests.post(f"{self.server_url}/license/heartbeat",
                        json={"license_key": self.license_key, "device_id": self.device_id}, timeout=10)
                except: pass
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True).start()

    def verify_and_start(self, license_key):
        ok, result = self.verify(license_key)
        if ok:
            print(f"✅ License OK! User: {self.user_name}, Expires: {self.expire_at}")
            self.start_heartbeat()
            return True
        print(f"❌ {result}")
        sys.exit(1)
```

## USAGE (thêm vào đầu main của tool)
```python
# Thay 2 giá trị này:
LICENSE_SERVER = "http://localhost:8000"
TOOL_CODE = "VER_PHONE_VEO"  # code tool trên admin panel

lm = LicenseManager(LICENSE_SERVER, TOOL_CODE)
key = input("Nhập license key: ").strip()
lm.verify_and_start(key)
# Tool chạy bình thường từ đây...
```

## RULES
- Chỉ verify 1 lần khi khởi động, KHÔNG verify mỗi action
- Heartbeat chạy background daemon thread, 5 phút/lần
- Device ID phải ổn định (MAC address), KHÔNG dùng random
- Timeout requests = 10s
- Chỉ cần check `data["valid"] == True`
