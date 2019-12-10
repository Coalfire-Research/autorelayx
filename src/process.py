#!/usr/bin/env python3

from subprocess import Popen, PIPE, STDOUT, call
import os
import time
import signal


class ProgramError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)


class Process:

    def __init__(self, cmd):
        self.proc = None
        self.cmd = cmd
        if '"' in self.cmd: # for commands like ntlmrelayx that may have secondary commands in them
            dquote_split = cmd.split('"')
            self.cmd_split = dquote_split[0].split()
            quoted_cmd = dquote_split[1]
            self.cmd_split.append(quoted_cmd)
        else:
            self.cmd_split = cmd.split()

    def run(self, logfile=None):
        """
        Run a program and log output
        """
        out = PIPE
        if logfile:
            out = open(logfile, 'a+')

        self.proc = Popen(self.cmd_split, stdout=out, stderr=out)

        return self.proc


    def kill(self, wait_time=0):
        """
        Kill a proc and optionally wait some time for it to die
        """
        if not self.proc:
            raise ProgramError("Cannot get PID, no program running")

        os.kill(self.proc.pid, signal.SIGINT)
        time.sleep(wait_time)
        self.proc.communicate()  # Prevent defunct processes

        # Confirm the proc is dead
        try:
            print(os.kill(self.proc.pid, 0))
        except ProcessLookupError:
            return True

        raise ProgramError(f"PID {self.proc.pid} failed to shut down cleanly")


    @property
    def pid(self):
        if self.proc == None:
            raise ProgramError("Cannot get PID, no program running")
        return self.proc.pid

