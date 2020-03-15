#!/usr/bin/env python3

from subprocess import Popen
import os
from src.utils import *
from signal import SIGINT


class ProgramError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)


class Process:

    def __init__(self, cmd, name):
        self.cmd = cmd
        self.escalation_successful = False
        self.name = name
        self.stdout = []
        if '"' in self.cmd: # for commands like ntlmrelayx that may have secondary commands in them
            dquote_split = cmd.split('"')
            self.cmd_split = dquote_split[0].split()
            quoted_cmd = dquote_split[1]
            self.cmd_split.append(quoted_cmd)
        else:
            self.cmd_split = cmd.split()

    def gather_remaining_output(self):
        with open(self.logfile, 'r+') as f:
            lines = f.readlines()
            stripped_lines = []
            for l in lines:
                stripped_lines.append(l.strip())
            if stripped_lines != self.stdout:
                new_output = (list(set(stripped_lines) - set(self.stdout)))
                for l in new_output:
                    self.stdout += l
                    print('    '+l)

    def run(self, logfile, live_output=False):
        """
        Run a program and log output
        """
        self.logfile = logfile
        log = open(logfile, "w+")
        self.logfile_obj = log
        self.proc = Popen(self.cmd_split, stdout=log, stderr=log, universal_newlines=True)

        try:
            if live_output == True:
                self.read_live()
        except KeyboardInterrupt:
            self.logfile_obj.close()
            self.gather_remaining_output()

        if live_output == True:
            self.gather_remaining_output()

        return self

    def kill(self, wait_time=0):
        """
        Kill a proc and optionally wait some time for it to die
        """
        if not self.proc:
            raise ProgramError("Cannot get PID, no program running")

        self.proc.communicate()  # Prevent defunct processes
        self.proc.send_signal(SIGINT)
        self.logfile_obj.close()
        time.sleep(wait_time)

        # Confirm the proc is dead
        try:
            print(os.kill(self.pid, 0))
        except ProcessLookupError:
            return True

        raise ProgramError(f"PID {self.proc.pid} failed to shut down cleanly")

    def read_live(self):
        log = open(self.logfile, "r+")
        file_lines = self.follow_file(log)
        for line in file_lines:
            line = line.strip()
            self.stdout.append(line)
            print('    ' + line)

            # Custom code
            self.parse_output(line)

    def follow_file(self, log):
        """
        Works like tail -f
        Follows a constantly updating file
        """
        log.seek(0, 2)
        while self.proc.poll() == None:
            line = log.readline()
            if not line:
                time.sleep(0.1)
                continue

            yield line

    @property
    def pid(self):
        if self.proc == None:
            raise ProgramError("Cannot get PID, no program running")
        return self.proc.pid

    # Custom parsing for autorelayx
    def parse_output(self, line):
        if 'Try using DCSync with secretsdump.py and this user' in line:
            self.escalation_successful = True
            print_good('Success! Dumping DC with secretsdump')
            print_info('Killing ntlmrelayx')
            self.kill()
        elif 'can now impersonate users on' in line:
            print_good('Success! Use getST.py from impacket to impersonate a user')
            self.kill()