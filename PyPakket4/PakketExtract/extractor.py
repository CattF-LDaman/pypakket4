
import os
import sys
import random
import time
import hashlib

import msgpack
from tempfile import gettempdir

from PakketShared.logger import Logger,INFO,WARNING,ERROR,DEBUG
from PakketShared.constants import MAGIC_NUM,MAGIC_NUM_LEN,VERSION
from PakketShared.compression import inflate
from PakketShared.crypto_aes import decrypt

class Extractor:

    def __init__(self, target_package, crypto_key = None, print_logs=True, print_debug_logs=False, stealth=False, skip_version_check=False):

        """

        :param target_package: Package to be extracted
        :param crypto_key: Key for decryption, blank if no encryption
        :param print_logs: Whether to print logs
        :param print_debug_logs: Whether to print debug logs
        :param stealth: If true, logs don't get printed or saved to a file, no log file is created.
        """

        self._stealth = stealth

        self._log_path = os.path.join(gettempdir(), "Extractor{}_{}.log".format(int(time.time()), random.randint(0, 999)))

        self.logger = Logger(self._log_path,print_logs=print_logs, print_debug=print_debug_logs, stealth=stealth)

        if not stealth:
            self.logger.log("Logger started with output file ' {} '".format(self._log_path))

        self.target_package = target_package

        self.crypto_key = crypto_key

        with open(self.target_package,"rb") as f:

            if f.read(MAGIC_NUM_LEN) != MAGIC_NUM:

                self.logger.log("Target isn't a valid PyPakket4 file!",ERROR)
                sys.exit(1)

            f.seek(-8, 2)
            self.header_pos = int.from_bytes(f.read(8),'little')

        self.logger.log('-- Extracting info from file header --')
        self.target_package_contents = {'files':[],'dirs':[]}

        with open(self.target_package,'rb') as f:
            f.seek(self.header_pos)

            self.version = int.from_bytes(f.read(2),'little')

            if self.version != VERSION and not skip_version_check:

                self.logger.log("Mismatching versions: PACKAGE: {}, PYPAKKET4: {}\n\tCannot proceed, to override version check set ' skip_version_check ' to True ".format(self.version,VERSION))
                sys.exit(1)

            else:

                self.logger.log("Mismatching versions: PACKAGE: {}, PYPAKKET4: {}\n\tStill trying to extract because ' skip_version_check ' is set to True!".format(self.version,VERSION))

            is_encrypted = True if f.read(1) == b"\x01" else False

            if is_encrypted and not crypto_key:

                self.logger.log("!! NO ENCRYPTION KEY GIVEN BUT PACKAGE HEADER SAYS CONTENTS HAVE BEEN ENCRYPTED, EXTRACTION WIL PROBABLY FAIL !!",WARNING)

            elif not is_encrypted and crypto_key:

                self.logger.log("You gave an encryption key but package is not encrypted!")

                crypto_key = self.crypto_key = None

            if is_encrypted:
                self.logger.log('Encryption enabled!',WARNING)
                self.IV = f.read(16)
            else:
                self.IV = None

            pckg_name_size = int.from_bytes(decrypt(f.read(1),crypto_key,self.IV),'little')
            pckg_name = decrypt(f.read(pckg_name_size),crypto_key,self.IV).decode('utf-8')

            self.logger.log("Package name: {}".format(pckg_name))

            metadata_size = int.from_bytes(decrypt(f.read(4),crypto_key,self.IV),'little')
            metadata = msgpack.loads(decrypt(f.read(metadata_size),crypto_key,self.IV))
            self.logger.log('Fetched metadata: {}'.format(metadata))

            amount_dirs = int.from_bytes(decrypt(f.read(6),crypto_key,self.IV),'little')

            for _ in range(amount_dirs):

                dirn_size = int.from_bytes(decrypt(f.read(1),crypto_key,self.IV),'little')
                dirn = decrypt(f.read(dirn_size),crypto_key,self.IV).decode('utf-8')

                self.target_package_contents['dirs'].append(dirn)

                self.logger.log("Found directory ' {} ' in file header".format(dirn))

            amount_files = int.from_bytes(decrypt(f.read(6),crypto_key,self.IV),'little')
            for _ in range(amount_files):

                fileo = {}

                filen_size = int.from_bytes(decrypt(f.read(1),crypto_key,self.IV),'little')
                fileo['name'] = decrypt(f.read(filen_size),crypto_key,self.IV).decode('utf-8')

                fileo['size'] = int.from_bytes(decrypt(f.read(8),crypto_key,self.IV),'little')

                fileo['hash'] = decrypt(f.read(32),crypto_key,self.IV)

                fileo['compressed_size'] = int.from_bytes(decrypt(f.read(8),crypto_key,self.IV),'little')

                fileo['dir_id'] = int.from_bytes(decrypt(f.read(4),crypto_key,self.IV),'little')

                fileo['last_mod_time'] = int.from_bytes(decrypt(f.read(8),crypto_key,self.IV),'little')

                fileo['base_offset_start'] = int.from_bytes(decrypt(f.read(8),crypto_key,self.IV),'little')

                fileo['chunksizes'] = []
                for _ in range(int.from_bytes(f.read(6),'little')):
                    fileo['chunksizes'].append(int.from_bytes(f.read(2),'little'))

                self.target_package_contents['files'].append(fileo)

                fpath = os.path.join(self.target_package_contents['dirs'][fileo['dir_id']], fileo['name'])

                self.logger.log("Found file ' {} ' in file header".format(fpath))

            self.logger.log("File header read.")

    def extract_package(self,output_dir,create_dir=True,allow_overwrites=False,skip_hash_check=False):

        if not os.path.isdir(output_dir):

            if create_dir:
                os.makedirs(output_dir,exist_ok=True)
            else:
                raise NotADirectoryError('Target is not a directory or does not exist')

        for dir in self.target_package_contents['dirs']:

            os.makedirs(os.path.join(output_dir,dir),exist_ok=True)

        with open(self.target_package,'rb') as pf:

            for file in self.target_package_contents['files']:

                fpath = os.path.join(self.target_package_contents['dirs'][file['dir_id']],file['name'])

                if (not os.path.exists(fpath) and not os.path.isfile(fpath)) or allow_overwrites:

                    with open(os.path.join(output_dir,os.path.join(self.target_package_contents['dirs'][file['dir_id']],file['name'])),'wb') as f:

                        h = hashlib.blake2b(digest_size=32)

                        pf.seek(file['base_offset_start'])

                        for cs in file['chunksizes']:

                            d = inflate(decrypt(pf.read(cs),self.crypto_key,self.IV))

                            h.update(d)

                            f.write(d)

                        if not skip_hash_check and h.digest() != file['hash']:

                            self.logger.log(" !! File ' {} ' failed hash check, package file might have been tampered with or corrupted !!".format(file['name']))

                        self.logger.log("File ' {} ' extracted.".format(file['name']))

                elif not allow_overwrites:
                    self.logger.log("Extractor tried to extract file ' {} ' but file already exists and allow_overwrites is set to false!".format(file),ERROR)
                    sys.exit(1)

        self.logger.log("All files extracted!")
