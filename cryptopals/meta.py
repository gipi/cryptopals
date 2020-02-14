def challenge(count):
    def _challenge(x):
        def _inner(*args, **kwargs):
            print('[+] challenge %d' % count)
            return x(*args, **kwargs)
        return _inner
    return _challenge

