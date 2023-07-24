from .sentinelone import SentinelOneBackend
from .sentinelone_pq import SentinelOnePQBackend

backends = {
    "sentinelone": SentinelOneBackend,
    "sentinelone_pq": SentinelOnePQBackend
}