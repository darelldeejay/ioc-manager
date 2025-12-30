
import re

with open('templates/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Find all script blocks
script_blocks = re.findall(r'<script>(.*?)</script>', content, re.DOTALL)

for i, block in enumerate(script_blocks):
    print(f"--- Script Block {i} ---")
    # Simple check for try/catch mismatch
    lines = block.split('\n')
    stack = []
    for line_no, line in enumerate(lines):
        if 'try {' in line:
            stack.append(line_no)
        if 'catch' in line or 'finally' in line:
            if stack:
                stack.pop()
    
    if stack:
        print(f"Warning: Potentially missing catch/finally for try at lines: {[l+1 for l in stack]}")
        for l in stack:
            start = max(0, l - 5)
            end = min(len(lines), l + 15)
            print("\n".join(lines[start:end]))
            print("-" * 20)
