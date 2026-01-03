
import re

TAG_RE = re.compile(r'<(/?\w+)([^>]*)>')
VOID_TAGS = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}

def parse_html(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    stack = []
    
    for i, line in enumerate(lines):
        # Remove comments crudely
        clean_line = re.sub(r'<!--.*?-->', '', line)
        
        matches = TAG_RE.finditer(clean_line)
        for m in matches:
            tag = m.group(1).lower()
            content = m.group(2)
            
            if tag.startswith('/'):
                # Closing tag
                tag_name = tag[1:]
                if not stack:
                    print(f"Line {i+1}: Error - Unexpected closing tag </{tag_name}> (Stack empty)")
                    continue
                
                if stack[-1][0] == tag_name:
                    stack.pop()
                else:
                    # Mismatch
                    # Try to find if we are closing a parent?
                    # or if we missed a closing somewhere
                    print(f"Line {i+1}: Error - Mismatched closing tag </{tag_name}>. Expected </{stack[-1][0]}> (opened at {stack[-1][1]})")
                    # Heuristic: if we find the tag deeper in stack, maybe we missed closes
                    found_idx = -1
                    for idx in range(len(stack)-1, -1, -1):
                        if stack[idx][0] == tag_name:
                            found_idx = idx
                            break
                    if found_idx != -1:
                        print(f"   -> closing everything down to {tag_name}")
                        while len(stack) > found_idx:
                            stack.pop()
                    else:
                        print("   -> ignoring stray close")

            else:
                # Opening tag
                tag_name = tag
                if tag_name in VOID_TAGS:
                    continue
                
                # Check for self-closing slash
                if content.strip().endswith('/'):
                    continue
                    
                stack.append((tag_name, i+1))

    if stack:
        print("\nUnclosed tags at EOF:")
        for t, l in stack:
            print(f"<{t}> opened at Line {l}")

print("Analyzing HTML structure...")
parse_html(r"c:\Users\darelldeejay\Downloads\GitHub\ioc-manager\templates\index.html")
