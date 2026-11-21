from llm_gateway.ratelimit import IpFailureTracker, RateLimiter, TokenBudget

from conftest import Clock


def test_bucket_allows_burst_then_blocks():
    clk = Clock()
    rl = RateLimiter(clock=clk)
    assert all(rl.allow("k", 3)[0] for _ in range(3))
    ok, retry = rl.allow("k", 3)
    assert not ok and retry > 0


def test_bucket_refills():
    clk = Clock()
    rl = RateLimiter(clock=clk)
    for _ in range(3):
        rl.allow("k", 3)
    clk.tick(21)
    assert rl.allow("k", 3)[0]


def test_buckets_are_per_key():
    clk = Clock()
    rl = RateLimiter(clock=clk)
    rl.allow("a", 1)
    assert not rl.allow("a", 1)[0]
    assert rl.allow("b", 1)[0]


def test_token_budget_daily_reset():
    clk = Clock(t=86400 * 100 + 10)
    tb = TokenBudget(clock=clk)
    tb.add("k", 70)
    assert tb.remaining("k", 100) == 30
    clk.tick(86400)
    assert tb.remaining("k", 100) == 100


def test_ip_tracker_blocks_and_expires():
    clk = Clock()
    t = IpFailureTracker(max_failures=3, window=60, block_for=100, clock=clk)
    assert not t.fail("1.2.3.4") and not t.fail("1.2.3.4")
    assert t.fail("1.2.3.4") and t.blocked("1.2.3.4")
    clk.tick(101)
    assert not t.blocked("1.2.3.4")


def test_ip_tracker_window_and_success():
    clk = Clock()
    t = IpFailureTracker(max_failures=3, window=10, clock=clk)
    t.fail("ip"), t.fail("ip")
    clk.tick(11)
    assert not t.fail("ip")
    t.success("ip")
    t.fail("ip")
    assert not t.blocked("ip")
