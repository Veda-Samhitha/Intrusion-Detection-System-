import time
import os

log_file = "alerts_only_log.txt"
seen = set()

print("Real-Time IDS Alerts Only:\n")

while True:
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            for line in f:
                if line not in seen:
                    print(line.strip())
                    seen.add(line)
    time.sleep(1)
