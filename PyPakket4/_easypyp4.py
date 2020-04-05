import re
import os

from .PakketExtract.extractor import Extractor
from .PakketCreate.creator import Creator

def package_directory(tdir,crypto_key=None,metadata=None,allow_overwrite=False,logs=False):

    _REGEXPATTERN = re.compile('\W')

    def to_alphanumeric(name: str):
        return re.sub(_REGEXPATTERN, '', name.replace(" ", "_"))


    n = to_alphanumeric(tdir)
    ni = 0

    while os.path.exists(n+str(ni)+".pyp4"):

        ni += 1

    pf = n+str(ni)+".pyp4"
    p = Creator(tdir,print_logs=logs)
    p.create_package_file(pf, encryption_key=crypto_key,metadata=metadata, allow_overwrite=allow_overwrite)
    p.close()

    return os.path.abspath(pf)

def extract_package(tpack,crypto_key=None,allow_overwrites=False,logs=False):

    p = Extractor(tpack, crypto_key=crypto_key, print_logs=logs)
    p.extract_package("{}_extract".format(tpack), allow_overwrites=allow_overwrites, add_metadata_file=True)
    p.close()