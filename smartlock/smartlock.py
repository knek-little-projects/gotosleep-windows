"""
Smartlock

Usage:
    smartlock [-h | --help]
    smartlock [--dry-run] [--log-level=LOGLEVEL] [--hhmm=HHMM]

Options:
    -s --dry-run
"""
import docopt
import logging
import psutil
import time
import os
import random
import datetime
import dateutil.tz
import dateutil.parser
import requests
import sys
import random
import ctypes
import re
import yaml

from enum import Enum


def is_admin():
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    return is_admin


def get_user():
    return os.getlogin()


def lock_user_screen(username):
    assert username == get_user()
    os.system('rundll32.exe user32.dll,LockWorkStation')


def gotosleep_lock_screen():
    os.system('schtasks /Run /TN "gotosleep-lock-screen"')


def set_user_password(username, password):
    assert is_admin()
    os.system('net user "%s" "%s"' % (username, password))


def shutdown():
    os.system('shutdown -s -f -t 00')


def get_random_insecure_password(maxrange=1000000):
    return "%d" % random.randint(0, maxrange)


def block_user(username):
    set_user_password(username, get_random_insecure_password())


def unblock_user(username):
    set_user_password(username, "")


class HHMM:
    def __init__(self, hh, mm):
        assert isinstance(hh, int)
        assert isinstance(mm, int)
        self.hh = hh
        self.mm = mm

    @classmethod
    def from_date(cls, dt: datetime.datetime):
        return HHMM(dt.hour, dt.minute)

    @classmethod
    def from_text(cls, s: str):
        s = s.strip()
        assert re.match("^[0-9]{2}:[0-9]{2}$", s)
        hh, mm = map(int, s.split(":"))
        assert 0 <= hh <= 23
        assert 0 <= mm <= 59
        return HHMM(hh, mm)

    def __str__(self):
        return "%02d:%02d" % (self.hh, self.mm)

    def __repr__(self):
        return "HHMM('%s')" % self

    def __lt__(self, other):
        return str(self) < str(other)

    def __eq__(self, other):
        return str(self) == str(other)

    def is_inside(self, start_from: "HHMM", end_before: "HHMM"):
        assert isinstance(start_from, HHMM)
        assert isinstance(end_before, HHMM)

        now = str(self)
        start_from = str(start_from)
        end_before = str(end_before)

        if start_from < end_before:
            return start_from <= now < end_before

        else:
            return start_from <= now or now < end_before


def get_file_info(exe, prop):
    import subprocess
    cmd = '''[System.Diagnostics.FileVersionInfo]::GetVersionInfo("%s").%s''' % (
        exe, prop)
    completed = subprocess.run(
        ["powershell", "-Command", cmd], capture_output=True)
    return completed.stdout


ALLOW_INSTANCES_PATH = "C:\\allow-exe.txt"
ALLOW_COMPANIES_PATH = "C:\\allow-cname.txt"


def killpx(dry_run=False):
    with open(ALLOW_INSTANCES_PATH) as input:
        allow_instances = {exe.strip()
                           for exe in input.read().strip().splitlines() if exe}

    with open(ALLOW_COMPANIES_PATH) as input:
        allow_companies = {cname.strip().encode()
                           for cname in input.read().strip().splitlines() if cname}

    for p in psutil.pids():
        try:
            p = psutil.Process(p)
            logging.debug("PSUTIL %s" % p.exe())

            if p.username() != 'qwe-ПК\\qwe':
                logging.debug("PSUTIL SKIP Username outside of scope")
                continue

            if p.exe() in allow_instances:
                logging.debug("PSUTIL SKIP Allowed instance")
                continue

            if not p.exe():
                logging.debug("PSUTIL SKIP None exe")
                continue

            cname = get_file_info(p.exe(), 'CompanyName')
            if any(allowed_substr in cname for allowed_substr in allow_companies):
                logging.debug("PSUTIL SKIP Allowed cname: %s" % cname)
                continue

            logging.info("KILL %s" % p.exe())
            if not dry_run:
                p.kill()

        except psutil.AccessDenied:
            continue

        except psutil.NoSuchProcess:
            continue

        except OSError:
            continue


HOSTS_LABEL = " # SMARTLOCK"
HOSTS_PATH = r'C:\Windows\System32\drivers\etc\hosts'
HOSTS_BLOCK_PATH = 'C:\\disallow-hosts.txt'

with open(HOSTS_BLOCK_PATH) as input:
    HOSTS_BLOCK = input.read().strip().split()


def block_inet():
    with open(HOSTS_PATH) as input:
        text = input.read()

    content = ["", HOSTS_LABEL + " START"]
    for host in HOSTS_BLOCK:
        content.append("0.0.0.0 %s %s" % (host, HOSTS_LABEL))

    content += [HOSTS_LABEL + " END"]
    content = "\n".join(content)

    if content in text:
        logging.info("HOSTS ALREADY BLOCKED")
        return

    logging.info("BLOCKING HOSTS")
    with open(HOSTS_PATH, 'w') as output:
        for line in text.split("\n"):
            if HOSTS_LABEL in line:
                continue

            output.write(line + "\n")

        output.write(content)


def unblock_inet():
    with open(HOSTS_PATH) as input:
        text = input.read()

    if HOSTS_LABEL not in text:
        logging.info("HOSTS ALREADY UNBLOCKED")
        return

    logging.info("UNBLOCKING HOSTS")
    with open(HOSTS_PATH, 'w') as output:
        for line in text.split("\n"):
            if HOSTS_LABEL in line:
                continue

            output.write(line + "\n")


def _load_config():
    CONFIG_PATH = "C:\\smartlock.yaml"

    with open(CONFIG_PATH) as config:
        config = yaml.safe_load(config.read())

    return config


def _extract_periods(config):
    periods = []

    if config["active"]:
        for period in config["periods"]:
            a, b = period.strip().split()
            periods.append((HHMM.from_text(a), HHMM.from_text(b)))

    return periods

_config = _load_config()
work_periods = _extract_periods(_config["work"])
dinner_periods = _extract_periods(_config["dinner"])
danger_periods = _extract_periods(_config["danger"])
critical_periods = _extract_periods(_config["critical"])


def in_periods(now, periods):
    for start_from, end_before in periods:
        if now.is_inside(start_from, end_before):
            return True


class Action(Enum):
    BLOCK_USER = 1
    BLOCK_ADMIN = 2
    BLOCK_ACTIVITIES = 3

    UNBLOCK_USER = 101
    UNBLOCK_ADMIN = 102
    UNBLOCK_ACTIVITIES = 103

    LOCK_USER_SCREEN = 200

    BREAK = 4


def get_actions(now):
    if now is None:
        return [
            Action.BLOCK_ADMIN,
            Action.BLOCK_USER,
            Action.LOCK_USER_SCREEN,
        ]

    actions = [
        Action.UNBLOCK_ADMIN,
        Action.UNBLOCK_USER,
        Action.UNBLOCK_ACTIVITIES,
    ]

    if in_periods(now, dinner_periods):
        actions += [
            Action.BLOCK_ADMIN,
            Action.BLOCK_USER,
            Action.LOCK_USER_SCREEN,
        ]

    if in_periods(now, work_periods):
        actions += [
            Action.BLOCK_ADMIN,
            Action.BLOCK_ACTIVITIES,
        ]

    if in_periods(now, danger_periods):
        actions += [
            Action.BLOCK_ADMIN
        ]

    if in_periods(now, critical_periods):
        actions += [
            Action.BLOCK_USER,
            Action.BLOCK_ADMIN,
            Action.LOCK_USER_SCREEN,
        ]

    return actions


def run_actions(actions, dry_run):
    do_block_admin = None
    do_block_user = None
    do_block_activities = None
    do_lock_user_screen = None

    for a in actions:
        if a == Action.BREAK:
            break

        elif a == Action.UNBLOCK_ACTIVITIES:
            do_block_activities = False

        elif a == Action.BLOCK_ACTIVITIES:
            do_block_activities = True

        elif a == Action.UNBLOCK_USER:
            do_block_user = False

        elif a == Action.BLOCK_USER:
            do_block_user = True

        elif a == Action.UNBLOCK_ADMIN:
            do_block_admin = False

        elif a == Action.BLOCK_ADMIN:
            do_block_admin = True

        elif a == Action.LOCK_USER_SCREEN:
            do_lock_user_screen = True

    if do_block_admin is True:
        logging.info("BLOCKING ADMIN")
        if not dry_run:
            block_user("admin")

    elif do_block_admin is False:
        logging.info("UNBLOCKING ADMIN")
        if not dry_run:
            unblock_user("admin")

    if do_block_user is True:
        logging.info("BLOCKING USER")
        if not dry_run:
            block_user("qwe")

    elif do_block_user is False:
        logging.info("UNBLOCKING USER")
        if not dry_run:
            unblock_user("qwe")

    if do_block_activities is True:
        logging.info("BLOCKING ACTIVITIES")
        killpx(dry_run=dry_run)
        if not dry_run:
            block_inet()

    elif do_block_activities is False:
        logging.info("UNBLOCKING ACTIVITIES")
        if not dry_run:
            unblock_inet()

    if do_lock_user_screen is True:
        logging.info("LOCK USER SCREEN")
        if not dry_run:
            gotosleep_lock_screen()


def _currentmillis():
    response = requests.get("https://currentmillis.com/time/minutes-since-unix-epoch.php")
    minutes = int(response.text)
    ts = minutes * 60
    date = datetime.datetime.utcfromtimestamp(ts).replace(tzinfo=dateutil.tz.gettz('UTC')).astimezone(dateutil.tz.gettz('MSC'))
    return date


def _tercdate():
    s = requests.get("https://terc.app").headers.get("Date")
    d = dateutil.parser.parse(s)
    d = d.astimezone(dateutil.tz.gettz('MSC'))
    return d


def find_time():
    try:
        return _currentmillis()
    except Exception as e:
        logging.error(str(e))

    try:
        return _tercdate()
    except Exception as e:
        logging.error(str(e))

    return None


if __name__ == "__main__":
    args = docopt.docopt(__doc__)
    log_level = args["--log-level"] or "INFO"
    is_dry_run = args["--dry-run"]
    logging.basicConfig(level=log_level, format='%(levelname)s %(asctime)-15s %(message)s')

    if is_dry_run:
        logging.warning("DRY RUN")

    if args["--hhmm"]:
        hhmm = HHMM.from_text(args["--hhmm"])
    else:
        now = find_time()
        if now:
            hhmm = HHMM.from_date(now)
        else:
            hhmm = None

    logging.info("Now is %s" % hhmm)
    run_actions(get_actions(hhmm), is_dry_run)
