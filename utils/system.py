import os
import platform
import socket
import getpass
from datetime import datetime


def get_username():
    return getpass.getuser()


def get_hostname():
    return socket.gethostname()


def get_os():
    return platform.system()


def get_os_version():
    return platform.release()


def get_python_version():
    return platform.python_version()


def get_current_time():
    return datetime.now().strftime("%H:%M:%S")


def get_current_date():
    return datetime.now().strftime("%Y-%m-%d")