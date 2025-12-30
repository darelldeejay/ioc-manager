
import pytest
from datetime import datetime, timedelta
from app import expand_input_to_ips, is_allowed_ip, dotted_netmask_to_prefix, _days_left

def test_dotted_netmask_to_prefix():
    assert dotted_netmask_to_prefix('255.255.255.0') == 24
    assert dotted_netmask_to_prefix('255.0.0.0') == 8
    assert dotted_netmask_to_prefix('255.255.255.255') == 32
    assert dotted_netmask_to_prefix('0.0.0.0') == 0

def test_expand_input_single():
    assert expand_input_to_ips("1.2.3.4") == ["1.2.3.4"]
    assert expand_input_to_ips("  8.8.8.8  ") == ["8.8.8.8"]

    ips = expand_input_to_ips("8.8.8.0/30")
    # net.hosts() for /30 returns 2 IPs (.1 and .2)
    assert len(ips) == 2
    assert "8.8.8.1" in ips
    assert "8.8.8.2" in ips

def test_expand_input_range():
    ips = expand_input_to_ips("1.1.1.1 - 1.1.1.3")
    assert sorted(ips) == ["1.1.1.1", "1.1.1.2", "1.1.1.3"]

def test_expand_invalid_input():
    with pytest.raises(ValueError):
        expand_input_to_ips("not-an-ip")
    with pytest.raises(ValueError):
        expand_input_to_ips("999.999.999.999")

def test_is_allowed_ip():
    # Assuming app blocks private/reserved (depends on your is_allowed_ip implementation)
    assert is_allowed_ip("8.8.8.8") is True
    assert is_allowed_ip("0.0.0.0") is False

def test_ttl_logic():
    now = datetime.now()
    # Permanent
    assert _days_left(now, 0) == 0
    # 1 Day
    assert _days_left(now, 1) == 1
    # Expired (5 days ago + 1 day TTL = -4 days left, capped at 0)
    past = now - timedelta(days=5)
    assert _days_left(past, 1) == 0
