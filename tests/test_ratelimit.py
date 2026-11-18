from alta_onetime.ratelimit import RateLimiter


class Clock:
    now = 0.0

    def __call__(self) -> float:
        return self.now


def test_idle_buckets_are_dropped_after_refill():
    clock = Clock()
    limiter = RateLimiter(2, 60, clock)
    limiter.allow("1.2.3.4")
    clock.now += 60
    limiter.prune()
    assert limiter.buckets == {}


def test_drained_bucket_survives_prune():
    clock = Clock()
    limiter = RateLimiter(1, 60, clock)
    limiter.allow("1.2.3.4")
    limiter.prune()
    assert "1.2.3.4" in limiter.buckets
