import datetime
import time


def get_POSIX_timestamp():

    return time.time()

def from_POSIX_timestamp(ts):

    return datetime.datetime.fromtimestamp(ts)

