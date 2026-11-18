"""Token bucket в памяти: ключ — IP или tg_id, состояние живёт только до рестарта."""

from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class Bucket:
    tokens: float
    stamp: float


@dataclass
class RateLimiter:
    capacity: int
    per_seconds: float
    clock: Callable[[], float]
    buckets: dict[str, Bucket] = field(default_factory=dict)

    def rate(self) -> float:
        return self.capacity / self.per_seconds

    def allow(self, key: str) -> bool:
        """Берёт один токен; False, если бакет пуст."""
        now = self.clock()
        bucket = self.buckets.get(key) or Bucket(float(self.capacity), now)
        bucket.tokens = min(self.capacity, bucket.tokens + (now - bucket.stamp) * self.rate())
        bucket.stamp = now
        self.buckets[key] = bucket
        if bucket.tokens < 1:
            return False
        bucket.tokens -= 1
        return True

    def prune(self) -> None:
        """Выкидывает бакеты, которые уже полностью восстановились: иначе словарь растёт от каждого IP."""
        now = self.clock()
        rate = self.rate()
        full = [k for k, b in self.buckets.items() if b.tokens + (now - b.stamp) * rate >= self.capacity]
        for k in full:
            del self.buckets[k]
