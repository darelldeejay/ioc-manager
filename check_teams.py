import os
import time
from dotenv import load_dotenv
from app import send_teams_alert

def verify():
    load_dotenv()
    url = os.getenv("TEAMS_WEBHOOK_URL")
    print(f"Loaded URL: {url[:30]}..." if url else "URL not set!")
    
    if not url:
        print("❌ TEAMS_WEBHOOK_URL is missing in .env")
        return

    print("Sending test alert...")
    send_teams_alert(
        title="🔔 Verification Test",
        text="Hello from IOC Manager! This is a **connectivity test**.",
        color="0076D7",
        sections=[
            {"activityTitle": "Status", "activitySubtitle": "Active ✅"},
            {"activityTitle": "Timestamp", "activitySubtitle": time.ctime()}
        ]
    )
    print("✅ Alert sent (async). Check your Teams channel in a few seconds.")
    # Wait a bit to let the thread run before script exit (since it's daemon)
    time.sleep(2)

if __name__ == "__main__":
    verify()
