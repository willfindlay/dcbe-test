#! /usr/bin/env python3

import os
import sys
import time
import signal
from typing import List

from bcc import BPF

from util import run_binary


def main() -> None:
    # Run tracee process
    pid = run_binary('./driver/driver')
    # Set flags
    flags = [f'-DPID={pid}']
    # Load BPF program
    with open('./bpf_program.c', 'r') as f:
        text = f.read()
    b = BPF(text=text, cflags=flags)
    # Set policy
    b.attach_uprobe(
        name='./driver/driver', sym='allowed', fn_name='allow_write'
    )
    b.attach_uretprobe(
        name='./driver/driver', sym='allowed', fn_name='deny_write'
    )
    # Signal tracee to start
    os.kill(pid, signal.SIGUSR1)
    while 1:
        b.trace_print()
        time.sleep(0.1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
