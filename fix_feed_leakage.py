import json
import os
from app import load_lines, save_lines, FEED_FILE, FEED_FILE_BPE, FEED_FILE_TEST

META_FILE = os.path.join(os.path.dirname(__file__), 'ioc-meta.json')
CANONICAL_TAGS = {
    "bpe": "BPE",
    "multicliente": "Multicliente",
    "test": "Test"
}

def load_meta():
    if not os.path.exists(META_FILE):
        return {}
    with open(META_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def clean_feeds():
    print("--- Starting Feed Cleanup ---")
    
    # 1. Load Data
    multi_lines = load_lines(FEED_FILE)
    bpe_lines = load_lines(FEED_FILE_BPE)
    test_lines = load_lines(FEED_FILE_TEST)
    meta_root = load_meta()
    meta = meta_root.get("ip_details", {})
    
    # Helpers to parse IP from line
    def get_ip(line):
        return line.split("|")[0]
        
    multi_ips = {get_ip(l): l for l in multi_lines}
    bpe_ips = {get_ip(l): l for l in bpe_lines}
    
    # 2. Analyze Multicliente Feed
    moved_count = 0
    new_multi_lines = []
    
    for line in multi_lines:
        ip = get_ip(line)
        timestamp = line.split("|")[1] if "|" in line else ""
        ttl = line.split("|")[2] if line.count("|") > 1 else "0"
        
        ip_meta = meta.get(ip, {})
            
        tags = ip_meta.get("tags", [])
        
        # Normalize tags for check
        norm_tags = [t.upper() for t in tags]
        
        # CONDITION: If it HAS "BPE" but DOES NOT HAVE "MULTICLIENTE"
        # (And strictly, if it looks like a leak, usually it has ONLY BPE)
        is_bpe = "BPE" in norm_tags
        is_multi = "MULTICLIENTE" in norm_tags
        
        if is_bpe and not is_multi:
            print(f"[MOVE] IP {ip} is BPE-only but found in Multicliente. Moving to BPE feed.")
            
            # Add to BPE lines if not already there
            if ip not in bpe_ips:
                bpe_lines.append(line)
                bpe_ips[ip] = line # Update lookup
            
            moved_count += 1
            # Do NOT add to new_multi_lines (effectively deleting it from here)
        else:
            # Keep it
            new_multi_lines.append(line)
            
    # 3. Save Changes
    if moved_count > 0:
        print(f"Saving changes... Moved {moved_count} IPs.")
        save_lines(new_multi_lines, FEED_FILE)
        save_lines(bpe_lines, FEED_FILE_BPE)
        print("Done!")
    else:
        print("No leaks found. Feeds are clean.")

if __name__ == "__main__":
    clean_feeds()
