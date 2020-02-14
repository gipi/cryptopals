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

    def get_challenge(self, n):
        for sn, challenges in self.sets():
            for challenge in challenges:
                if n == challenge.n:
                    return sn, challenge

    def exec(self, n):
        sn, challenge = self.get_challenge(n)
        print(challenge.func.__doc__)
        challenge.func()


cryptopals = CryptoPals()
