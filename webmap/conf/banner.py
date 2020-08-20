#!/usr/bin/python3
import platform
from colorama import Fore, Style,init
if 'Windows' in platform.system():
    init(wrap=True)
else:
    init(autoreset=False)
print('welcome to this little auto tool  ~(> v < ~)')
