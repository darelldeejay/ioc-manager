import re

def validate_tags(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    stack = []
    # Only tracking structural tags we care about
    tags_to_track = ['div', 'form', 'ul', 'li', 'button', 'select', 'table', 'tbody', 'thead', 'tr', 'td', 'th']

    # Simple regex to find tags. Note: This is fragile for complex HTML but works for well-formatted templates.
    # We ignore self-closing tags (like <input ... /> or <br>) mostly.
    # We look for <tag...> and </tag>
    
    tag_re = re.compile(r'</?(\w+)[^>]*>')
    
    # We'll only focus on the section we edited: 300 to 800
    # But to be safe, we need context. However, context might be huge.
    # Let's start scanning from line 300, assuming stack is empty (or we'll see negative balance)
    
    # Actually, scanning from start is safer.
    
    # Let's limit scope to lines 300-800 and just check relative balance
    # If we see more closes than opens, we know we missed an open.
    # If we end with positive stack, we missed a close.
    
    balance = {t: 0 for t in tags_to_track}
    
    for i, line in enumerate(lines):
        if i < 300 or i > 800: continue
        
        matches = tag_re.finditer(line)
        for m in matches:
            raw = m.group(0)
            tag = m.group(1).lower()
            
            if tag not in tags_to_track: continue
            
            if raw.startswith('</'):
                # Closing
                balance[tag] -= 1
                # print(f"L{i+1}: Closing {tag} -> {balance[tag]}")
            else:
                # Opening
                # Check if self-closing by convention or syntax
                # HTML5 void elements (br, hr, input, etc) are not in our list except maybe... 
                # None of our tracked tags are void elements.
                # But assume standard formatting.
                balance[tag] += 1
                # print(f"L{i+1}: Opening {tag} -> {balance[tag]}")

    print("Balance from line 300 to 800 (Positive = Unclosed, Negative = Extra Close):")
    for t in balance:
        if balance[t] != 0:
            print(f"{t}: {balance[t]}")

validate_tags(r"c:\Users\darelldeejay\Downloads\GitHub\ioc-manager\templates\index.html")
