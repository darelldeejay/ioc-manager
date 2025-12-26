def days_remaining(date_str, ttl_str):
    try:
        ttl = int(ttl_str)
        if ttl == 0:
            return None
        d = datetime.strptime(date_str, "%Y-%m-%d")
        exp = d + timedelta(days=ttl)
        left = (exp - _now_utc().replace(tzinfo=None)).days
        return max(0, left)
    except:
        return None
