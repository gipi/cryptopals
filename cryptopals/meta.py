class Challenge(object):

    def __init__(self, number, description, func):
        self.n = number
        self.func = func
        self.description = description


class CryptoPals(object):
    _SETS = {}

    def challenge(self, _set, count, title):

        def _challenge(x):
            s = self._SETS.setdefault(_set, [])
            s.append(Challenge(count, title, x))

            def _inner(*args, **kwargs):
                print('[+] challenge %d' % count)
                return x(*args, **kwargs)
            return _inner
        return _challenge

    def sets(self):
        return self._SETS.items()


cryptopals = CryptoPals()
