from .sentinelonedeepvisibility import SentinelOneDeepVisibilityBackend

backends = {        # Mapping between backend identifiers and classes. This is used by the pySigma plugin system to recognize backends and expose them with the identifier.
    "sentinelonedeepvisibility": SentinelOneDeepVisibilityBackend,
}