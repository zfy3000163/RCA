#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import time
import collect_log
import iptables_trace

def main():
    log_collecter = collect_log.CollectLog()
    iptc_opt = iptables_trace.IptcOpt()

    path='/var/log/kern.log'
    log_collecter.thread_startup(path, {})
    time.sleep(int(sys.argv[1]))
    log_collecter.thread_status()
    logs = log_collecter.thread_stop()

    if logs:
        for log in logs:
            result=iptc_opt.trace_packet('eth0', log)



main()

