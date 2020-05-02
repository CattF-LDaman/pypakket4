import colorama
import datetime

from os import remove

import json

colorama.init(autoreset=True)

INFO = 0
WARNING = 1
ERROR = 2
UNKNOWN = 3
DEBUG = -1

class Logger:

    types = {0:('INFO',colorama.Fore.WHITE),1:('WARNING',colorama.Fore.LIGHTMAGENTA_EX),2:('ERROR',colorama.Fore.LIGHTRED_EX),3:('UNKNOWN',colorama.Fore.LIGHTBLUE_EX),-1:("DEBUG",colorama.Fore.LIGHTGREEN_EX)}

    def __init__(self,filepath,print_logs=True,print_debug=False,stealth=False,cleanup=True):

        self._cleanup = cleanup

        self._stealth = stealth

        if not stealth:
            self.log_file = open(filepath,'a')

            self.filepath = filepath

            self.print_logs = print_logs
            self.print_debug = print_debug

    def log(self,log,type=0):

        if not self._stealth:
            if type not in Logger.types:

                raise KeyError('Invalid log type')

            cur_time = datetime.datetime.now().strftime("%d/%m/%Y @ %H:%M:%S")

            log_dict = {"type":type,"type_description":Logger.types[type][0],"content":log,"timestamp":cur_time}

            self.log_file.write(json.dumps(log_dict)+'\n')
            self.log_file.flush()

            log_text = "[{}] {}".format(Logger.types[type][0],log)

            if self.print_logs:
                if type != DEBUG or self.print_debug:
                    print(Logger.types[type][1]+log_text)

    def close(self):

        if self._stealth:

            self.log("Closing logger.")

            if not self.log_file.closed:
                self.log_file.close()

            if self._cleanup:

                remove(self.filepath)
