try:
    import aiohttp.resolver as _resolver
    import aiohttp.connector as _connector
    _resolver.DefaultResolver = _resolver.ThreadedResolver
    _connector.DefaultResolver = _resolver.ThreadedResolver
except Exception:
    pass
