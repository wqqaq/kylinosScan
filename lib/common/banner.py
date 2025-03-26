# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import random
from lib.common.cmd import CommandLines


Version = 'kylinosScan1202'
red = '\033[25;31m'
green = '\033[25;32m'
yellow = '\033[25;33m'
blue = '\033[25;34m'
Fuchsia = '\033[25;35m'
cyan = '\033[25;36m'
end = '\033[0m'
colors = [red,green,yellow,blue,Fuchsia,cyan]

Banner1 = """{}
 _______________
< kylinos scan >
 ---------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\\
                ||----w |
                ||     ||
           {}
""".format(random.choice(colors),Version,end)

def RandomBanner():
    cmd_instance = CommandLines()
    if cmd_instance.cmd.silent is None:
        print(Banner1)
        print("©2024 wenq8")

