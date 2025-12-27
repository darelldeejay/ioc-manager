import time
from app import teams_aggregator

def verify_batching():
    print("🧪 Starting Aggregator Verification...")
    
    # 1. Simulate adding IPs via API
    print("1. Simulating bulk additions...")
    teams_aggregator.add_batch(
        added_items=[
            {"ip": "1.1.1.1", "tags": ["BPE"], "ttl": 30, "alert_id": "TICKET-1"},
            {"ip": "2.2.2.2", "tags": ["Multicliente"], "ttl": 7, "alert_id": "TICKET-1"}
        ],
        updated_items=[],
        user="TestUser",
        source="api"
    )
    
    teams_aggregator.add_batch(
        added_items=[],
        updated_items=[
            {"ip": "3.3.3.3", "tags": ["BPE"], "old_ttl": 5, "new_ttl": 30}
        ],
        user="TestUser",
        source="api"
    )
    
    print("   -> Events added to buffer.")
    
    # 2. Check buffer size (internal check, abusing public access for test)
    with teams_aggregator.buffer_lock:
        print(f"   -> Buffer size: {len(teams_aggregator.buffer)} (Expected 3)")
    
    # 3. Force Flush
    print("2. Forcing Flush...")
    teams_aggregator.flush()
    print("✅ Flush called. Check Teams for '🔔 Resumen IOC Manager (3 eventos)'.")

if __name__ == "__main__":
    verify_batching()
