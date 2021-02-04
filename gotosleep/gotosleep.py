from datetime import datetime as dt
from dateutil import tz
import os
import random

ADMIN = "admin"
USER = "Restricted"
ADMIN_PASS = "ADMIN PASSWORD"
USER_PASS = "USER PASSWORD"
TIMEZONE = tz.gettz('Europe/Moscow')

RANDOM_PASS = "pwd%04d" % random.randint(0, 1000)

now = dt.now().astimezone(TIMEZONE)
now = "%02d:%02d" % (now.hour, now.minute)
print(now)

def chpass(user, password):
  os.system('net user "%s" "%s"' % (user, password))


def poweroff():
  os.system('rundll32.exe user32.dll,LockWorkStation')


def isseq(a, b, c):
  if a <= c:
    return a <= b <= c
  else:
    return a <= b or b <= c

assert isseq("23:00", "01:00", "04:00")
assert not isseq("00:00", "13:00", "05:00")

chpass(ADMIN, ADMIN_PASS)
chpass(USER, USER_PASS)

if isseq("17:00", now, "05:00"):
  chpass(ADMIN, RANDOM_PASS)

if isseq("23:00", now, "05:00"):
  chpass(USER, RANDOM_PASS)
  poweroff()
