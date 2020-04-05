
import os
import random
import time
import hashlib

import pprint
import msgpack
from tempfile import gettempdir

from PyPakket4.PakketShared.logger import Logger,INFO,WARNING,ERROR,DEBUG
from PyPakket4.PakketShared.constants import MAGIC_NUM,MAGIC_NUM_LEN,VERSION
from PyPakket4.PakketShared.compression import inflate
from PyPakket4.PakketShared.crypto_aes import decrypt
from PyPakket4.PakketShared.pp4time import from_POSIX_timestamp
from PyPakket4.PakketExtract.exceptions import *

class Extractor:

    def __init__(self, target_package, crypto_key = None, print_logs=True, print_debug_logs=False, stealth=False, logger_cleanup=True, skip_version_check=False):

        """

        :param target_package: Package (path) to be extracted
        :param crypto_key: Key for decryption, blank if no encryption
        :type crypto_key: String
        :param print_logs: Whether to print logs
        :param print_debug_logs: Whether to print debug logs
        :param stealth: If true, logs don't get printed or saved to a file, no log file is created.
        :param logger_cleanup: Whether to delete logfile when logger.close method is called
        :param skip_version_check: Skip checking 16-bit version end included in file header, if set to False, Extractor raises PyPakket4.PakketExtract.exceptions.VersionMismatchError
        """

        self.closed = False

        self._stealth = stealth

        self._log_path = os.path.join(gettempdir(), "Extractor{}_{}.log".format(int(time.time()), random.randint(0, 999)))

        self.logger = Logger(self._log_path,print_logs=print_logs, print_debug=print_debug_logs, stealth=stealth, cleanup=logger_cleanup)

        if not stealth:
            self.logger.log("Logger started with output file ' {} '".format(self._log_path))

        self.target_package = target_package

        self.crypto_key = crypto_key

        with open(self.target_package,"rb") as f:

            if f.read(MAGIC_NUM_LEN) != MAGIC_NUM:

                self.logger.log("Target isn't a valid PyPakket4 file!",ERROR)

            f.seek(-8, 2)
            self.header_pos = int.from_bytes(f.read(8),'little')

        self.logger.log('-- Extracting info from file header --')
        self.target_package_contents = {'files':[],'dirs':[]}

        with open(self.target_package,'rb') as f:
            f.seek(self.header_pos)

            self.version = int.from_bytes(f.read(2),'little')

            if self.version != VERSION:
                if not skip_version_check:

                    self.logger.log("Mismatching versions: PACKAGE: {}, PYPAKKET4: {}\n\tCannot proceed, to override version check set ' skip_version_check ' to True ".format(self.version,VERSION))
                    raise VersionMismatchError("16-bit version int found in file header doesn't match current PyPakket4 version")

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
            self.pckg_name = decrypt(f.read(pckg_name_size),crypto_key,self.IV).decode('utf-8')

            self.logger.log("Package name: {}".format(self.pckg_name))

            metadata_size = int.from_bytes(decrypt(f.read(4),crypto_key,self.IV),'little')
            self.metadata = msgpack.loads(decrypt(f.read(metadata_size),crypto_key,self.IV))
            self.logger.log('Fetched metadata: {}'.format(self.metadata))

            self.creation_time = int.from_bytes(decrypt(f.read(8),crypto_key,self.IV),'little')
            self.creation_time_as_str = from_POSIX_timestamp(self.creation_time)
            self.logger.log('Creation time: {}'.format(self.creation_time_as_str))

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

    def extract_package(self, output_dir, create_dir=True, allow_overwrites=False, skip_hash_check=False, hash_match_required=False, add_metadata_file=False):
        """

        :param output_dir: Directory to act as root dir found in file header
        :param create_dir: Whether to create ' output_dir ' if it doesn't exist, if set to False and output_dir doesn't exist, NotADirectoryError is raised
        :param allow_overwrites: Whether to overwrite if file that needs to be extracted already exists in ' output_dir ', if set to False, PyPakket4.PakketExtract.exceptions.ExtractOverwriteError is raised
        :param skip_hash_check: Whether to skip checking hash found in file header and hash of extracted file
        :param hash_match_required: Whether to raise error if hash check fails (see skip_hash_check)
        :param add_metadata_file: Whether to add file containing metadata
        :return: None
        """

        if self.closed:
            raise ExtractorClosedError("Can't extract with closed Extractor object")

        if not os.path.isdir(output_dir):

            if create_dir:
                os.makedirs(output_dir,exist_ok=True)
            else:
                raise NotADirectoryError("Target is not a directory or does not exist, to create directory automatically enable ' create_dir '")

        for dir in self.target_package_contents['dirs']:

            os.makedirs(os.path.join(output_dir,dir),exist_ok=True)

        with open(self.target_package,'rb') as pf:

            for file in self.target_package_contents['files']:

                fpath = os.path.join(output_dir,os.path.join(self.target_package_contents['dirs'][file['dir_id']],file['name']))

                if (not os.path.exists(fpath) and not os.path.isfile(fpath)) or allow_overwrites:

                    with open(fpath,'wb') as f:

                        if not skip_hash_check:
                            h = hashlib.blake2b(digest_size=32)

                        pf.seek(file['base_offset_start'])

                        for cs in file['chunksizes']:

                            d = inflate(decrypt(pf.read(cs),self.crypto_key,self.IV))

                            if not skip_hash_check:
                                h.update(d)

                            f.write(d)

                        if not skip_hash_check and h.digest() != file['hash']:

                            self.logger.log(" !! File ' {} ' failed hash check, package file might have been tampered with, is corrupted or extraction failed !!".format(file['name']))
                            if hash_match_required:
                                raise HashMismatchError("File ' {} ' failed hash check, package file might have been tampered with, is corrupted or extraction failed".format(file['name']))

                        self.logger.log("File ' {} ' extracted.".format(file['name']))

                    os.utime(fpath, (file['last_mod_time'],file['last_mod_time']))
                    self.logger.log("Changed last modification time of file to match file['last_mod_time']",DEBUG)

                elif not allow_overwrites:
                    self.logger.log("Extractor tried to extract file ' {} ' but file already exists and allow_overwrites is set to false!".format(file),ERROR)
                    raise ExtractOverwriteError("Extractor tried to extract file ' {} ' but file already exists and allow_overwrites is set to false!".format(file))

        self.logger.log("All files extracted!")

        if add_metadata_file:
            self.logger.log("Creating file containing metadata...")
            with open(os.path.join(output_dir,"pyp4_metadata.txt"),'w') as f:
                h = """This file was generated by PyPakket4 and wasn't in the original package file
                
"""
                f.write(h)
                f.write("PyPakket4 version: {}\n".format(self.version))
                f.write("Created on: {}\n".format(self.creation_time_as_str))
                f.write("Metadata: ")
                pprint.pprint(self.metadata,f)
                f.write("\n-- END OF FILE --")
            self.logger.log("Metadata file created.")

        self.logger.log("Done.")

    def close(self):

        self.closed = True

        self.logger.log("Closing.")
        self.logger.close()