
import os
import random
import time
import hashlib

import msgpack
from tempfile import gettempdir

from PyPakket4.PakketShared.logger import Logger,INFO,WARNING,ERROR,DEBUG
from PyPakket4.PakketShared.crypto_aes import encrypt,gen_iv
from PyPakket4.PakketShared.constants import MAGIC_NUM,MAGIC_NUM_LEN,VERSION
from PyPakket4.PakketShared.compression import deflate
from PyPakket4.PakketShared.pp4time import get_POSIX_timestamp
from PyPakket4.PakketCreate.exceptions import *

class Creator:

    def __init__(self,target_dir,package_name=None,print_logs=True,print_debug_logs=False,stealth=False,logger_cleanup=True):

        """

        :param target_dir: Directory to be archived (path)
        :param print_logs: Whether to print logs
        :param print_debug_logs: Whether to print debug logs
        :param stealth: If true, logs don't get printed or saved to a file, no log file is created.
        """

        self.closed = False

        self._stealth = stealth

        self._log_path = os.path.join(gettempdir(),"Creator{}_{}.log".format(int(time.time()),random.randint(0,999)))

        self.logger = Logger(self._log_path,print_logs=print_logs,print_debug=print_debug_logs,stealth=stealth,cleanup=logger_cleanup)

        if not stealth:
            self.logger.log("Logger started with output file ' {} '".format(self._log_path))

        self.target_dir = target_dir

        self.target_dir_contents = {"files":[], "dirs":[]} # Q: Unsigned long long (64-bit) (8 bytes)

        self.package_name = os.path.basename(self.target_dir) if not package_name else package_name

        if not os.path.exists(target_dir):
            raise FileNotFoundError('Directory " {} " not found'.format(target_dir))

        d_i_counter = 0
        for root,dirs,files in os.walk(self.target_dir):

            dr = os.path.relpath(root,self.target_dir)
            self.target_dir_contents["dirs"].append(dr)
            self.logger.log("Added dir {} to collection dict".format(" ' %s ' " % dr if dr != '.' else "PACKAGE ROOT"))

            for file in files:
                s = os.path.getsize(os.path.join(root,file))

                fileo = {"name":file,"size":s,"abs_path":os.path.join(root,file),"rel_path":os.path.join(os.path.relpath(root,self.target_dir),file),"dir_id":d_i_counter,"last_mod_time":int(os.path.getmtime(os.path.join(root,file)))}
                self.target_dir_contents['files'].append(fileo)

                self.logger.log("Added file ' {} ' to collection dict".format(fileo['rel_path']))

            d_i_counter += 1

        self.logger.log("Creator with directory ' {} ' initialised!".format(os.path.basename(target_dir)))

    def create_package_file(self,out_path,encryption_key=None,metadata=None,allow_overwrite=False, file_write_chunk_size = 2048, overwrite_timestamp=None):

        """

        Extract files from loaded package file to a directory

        :param out_path: Path to output file
        :type out_path: any path-like object/string
        :param encryption_key: Encryption key, blank for no encryption
        :type encryption_key: string
        :param metadata: Optional extra metadata
        :type metadata: Any object serializable by msgpack, usually dict
        :param allow_overwrite: Allow overwrite if output file already exists
        :param file_write_chunk_size: Chunk size per write
        :param overwrite_timestamp: When given, sets creation time of package to given int (number of seconds since unix epoch), does NOT overwrite file modification times
        :return: None
        """

        if self.closed:

            raise CreatorClosedError("Can't extract with closed Creator object")

        if os.path.exists(out_path) and not allow_overwrite:

            raise FileExistsError("Output file already exists")

        elif os.path.exists(out_path) and allow_overwrite:

            with open(out_path,'wb') as f:
                pass

        if encryption_key:

            self.logger.log("Encryption enabled!",WARNING)

        with open(out_path,'ab') as f:

            f.write(MAGIC_NUM)

            self.logger.log("PyPakket4 magic number written to package file",DEBUG)

            self.IV = gen_iv()

            #rel_index_start = original_start = f.tell()

            for filen,file in enumerate(self.target_dir_contents['files']):

                self.target_dir_contents['files'][filen]['base_offset_start'] = f.tell()

                with open(file['abs_path'],'rb') as ff:

                    d = "T"

                    h = hashlib.blake2b(digest_size=32)

                    cn = 0

                    ts = 0

                    self.target_dir_contents['files'][filen]['chunksizes'] = []

                    while len(d) > 0:

                        cn += 1
                        d = ff.read(file_write_chunk_size)

                        if len(d) != 0:
                            self.logger.log("File ' {} ' : CHUNK {} : {}".format(file['name'],cn,len(d)),DEBUG)

                        h.update(d)
                        dc = deflate(d)
                        if encryption_key:
                            dc = encrypt(dc, encryption_key, self.IV)
                        ts += len(dc)

                        self.target_dir_contents['files'][filen]['chunksizes'].append(len(dc))

                        f.write(dc)
                        f.flush()

                    self.target_dir_contents['files'][filen]['compressed_size'] = ts
                    self.target_dir_contents['files'][filen]['hash'] = h.digest()

                    #print(self.target_dir_contents['files'][filen]['chunks'], len(self.target_dir_contents['files'][filen]['chunks']))

                self.logger.log("<< {}/{} - {}% >> File ' {} ' has been written to package file".format(filen+1,len(self.target_dir_contents['files']),int((filen+1)/len(self.target_dir_contents['files'])*100),file['name']))

                f.write(h.digest())

                #print(original_start+file['base_offset_start'])
                #print(rel_index_start,rel_index_start+file['size']+32 , f.tell())

                #rel_index_start += (file['size']+32)

            header_offset = f.tell()

            f.write(VERSION.to_bytes(2,'little'))

            if not encryption_key:
                f.write(b"\x00")
            else:
                f.write(b"\x01")

            if encryption_key:

                f.write(self.IV)

            f.write(encrypt(len(self.package_name.encode('utf-8')).to_bytes(1, 'little'),encryption_key,self.IV))
            f.write(encrypt(self.package_name.encode('utf-8'),encryption_key,self.IV))

            mdata = msgpack.dumps(metadata)
            f.write(encrypt(len(mdata).to_bytes(4, 'little'),encryption_key,self.IV))  # max mdata len (theoretical) == 2**32-1
            f.write(encrypt(mdata,encryption_key,self.IV))

            self.logger.log("Metadata has been written to package file")

            ts = get_POSIX_timestamp() if not overwrite_timestamp else overwrite_timestamp

            f.write(encrypt(int(ts).to_bytes(8,'little'),encryption_key,self.IV))

            f.write(encrypt(len(self.target_dir_contents['dirs']).to_bytes(6, 'little'),encryption_key,self.IV))

            for dir in self.target_dir_contents['dirs']:
                f.write(encrypt(len(dir).to_bytes(1, "little"),encryption_key,self.IV))
                f.write(encrypt(dir.encode('utf-8'),encryption_key,self.IV))

                self.logger.log("Directory ' {} ' has been written to file header".format(dir))


            f.write(encrypt(len(self.target_dir_contents['files']).to_bytes(6, 'little'),encryption_key,self.IV))

            # {"name":str,"size":int,"rel_path":str,"dir_id":int"last_mod_time":int, "base_offset_start": int}

            for file in self.target_dir_contents['files']:
                file_entry = b""
                file_entry += encrypt(len(file['name']).to_bytes(1, "little"),encryption_key,self.IV)
                self.logger.log("Filename length of file ' {} ' added to file entry".format(file['name']), DEBUG)
                file_entry += encrypt(file['name'].encode('utf-8'),encryption_key,self.IV)
                self.logger.log("Filename of file ' {} ' added to file entry".format(file['name']), DEBUG)

                file_entry += encrypt(file['size'].to_bytes(8, 'little'),encryption_key,self.IV)  # 64-BIT
                self.logger.log("File size of file ' {} ' added to file entry".format(file['name']), DEBUG)

                file_entry += encrypt(file['hash'],encryption_key,self.IV)

                file_entry += encrypt(file['compressed_size'].to_bytes(8, 'little'),encryption_key,self.IV)  # 64-BIT
                self.logger.log("File compressed size of file ' {} ' added to file entry".format(file['name']), DEBUG)

                #file_entry += encrypt(len(file['rel_path']).to_bytes(4, "little"),encryption_key,self.IV)
                #self.logger.log("Relative path length of file ' {} ' added to file entry".format(file['name']),DEBUG)
                #file_entry += encrypt(file['rel_path'].encode('utf-8'),encryption_key,self.IV)
                #self.logger.log("Relative path of file ' {} ' added to file entry".format(file['name']), DEBUG)

                file_entry += encrypt(file['dir_id'].to_bytes(4, "little"),encryption_key,self.IV)
                self.logger.log("Directory id of file ' {} ' added to file entry".format(file['name']), DEBUG)

                file_entry += encrypt(file['last_mod_time'].to_bytes(8, 'little'),encryption_key,self.IV)
                self.logger.log("Last modification time of file ' {} ' added to file entry".format(file['name']),DEBUG)

                file_entry += encrypt(file['base_offset_start'].to_bytes(8, 'little'),encryption_key,self.IV)
                self.logger.log("Base offset of file ' {} ' added to file entry".format(file['name']), DEBUG)

                f.write(file_entry)

                f.write(len(file['chunksizes']).to_bytes(6,'little'))

                for cs in file['chunksizes']:

                    f.write(cs.to_bytes(2,'little'))

                self.logger.log("Chunk sizes of file ' {} ' written to package file".format(file['name']),DEBUG)

                self.logger.log("File entry for file ' {} ' has been written to package file".format(file['name']))

            f.write(header_offset.to_bytes(8,'little'))
            self.logger.log("Header offset {}".format(header_offset),DEBUG)

            f.flush()

        self.logger.log("Package file created!")

    def close(self):

        self.closed = True

        self.logger.log("Closing.")
        self.logger.close()