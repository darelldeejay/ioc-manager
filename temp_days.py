
# Valid definition to ensure Index route doesn't crash or return valid data
def days_remaining(added_at_arg, ttl_arg):
    try:
        ttl = int(ttl_arg)
    except:
        return None # Infinite or Invalid

    if ttl <= 0:
        return None # Infinite

    if not added_at_arg:
        return None

    try:
        # Try Parsing ISO
        dt = datetime.fromisoformat(str(added_at_arg).replace("Z", "+00:00"))
        if dt.tzinfo:
            dt = dt.replace(tzinfo=None)
    except:
        try:
            dt = datetime.strptime(str(added_at_arg), "%Y-%m-%d")
        except:
            return None # Cannot parse date

    delta = (datetime.now() - dt).days
    left = ttl - delta
    return left if left >= 0 else 0
