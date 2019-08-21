#!/usr/bin/env python3

from subprocess import Popen
import os
import time


class ProgramError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)


class Program:

    def __init__(self):
        self.proc = None


    def run(self, cmd_split, logfile=None):
        """
        Run a program and log output
        """
        if not logfile:
            self.proc = Popen(cmd_split, stdout=PIPE, stderr=PIPE)
        else:
            f = open(logfile, 'a+')
            self.proc = Popen(cmd_split, stdout=f, stderr=STDOUT)

        return self.proc


    def kill(self, wait_time=0):
        if self.proc == None:
            raise ProgramError("Cannot get PID, no program running")
        ret = os.kill(self.proc.pid, signal.SIGINT)
        time.sleep(wait_time)
        return ret


    @property
    def pid(self):
        if self.proc == None:
            raise ProgramError("Cannot get PID, no program running")
        return self.proc.pid

