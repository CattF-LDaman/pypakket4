import datetime
import time


def get_POSIX_timestamp():

    return time.time()

def from_POSIX_timestamp(ts):

    return datetime.datetime.fromtimestamp(ts).strftime("%d/%m/%Y (DD/MM/YYYY) at %T")

def current_timestamp():

    return datetime.datetime.now().strftime("%d/%m/%Y (DD/MM/YY) at %T")