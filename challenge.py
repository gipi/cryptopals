import sys
import logging

from cryptopals.meta import cryptopals
from cryptopals import sets


CHALLENGE = 5
logging.addLevelName(CHALLENGE, 'CHALLENGE')


def challenge_log(self, message, *args, **kwargs):
    self.log(CHALLENGE, message, *args, **kwargs)


logging.Logger.challenge = challenge_log

logger = logging.getLogger()
logger.setLevel('INFO')

# http://stackoverflow.com/a/16955098/1935366


if __name__ == "__main__":
    choice = None
    if len(sys.argv) == 2:
        choice = int(sys.argv[1])
    # https://mixmastamyk.bitbucket.io/
    from console import fg, fx, defx
    from console.screen import sc as screen
    from console.utils import wait_key, set_title, cls
    from console.constants import ESC

    exit_keys = (ESC, 'q', 'Q')

    cls()

    set_title('Cryptopals')
    with screen.location(4, 4):
        print(
            fg.lightgreen(f'** {fx.i}Cryptopals challenges! {defx.i}**'),
            screen.mv_x(5),  # back up, then down
            screen.down(40),
            fg.yellow(f'(Hit the {fx.reverse}ESC{defx.reverse} key to exit): '),
            end='', flush=True,
        )

    y = 10
    for sn, challenges in cryptopals.sets():
        y += 1
        with screen.location(2, y):
            print(fg.blue(f'Set {sn}'))
        y += 2
        for challenge in challenges:
            with screen.location(4, y):
                print(fg.blue(f'#{challenge.n} - {challenge.description}'))

            y += 1

    with screen.hidden_cursor():
        choice = wait_key() if not choice else choice
        cls()
        cryptopals.exec(int(choice))
