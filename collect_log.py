#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import time
import signal
import threading
import multiprocessing  as mulproc


class CollectLog():
    def __init__(self):
        self.thread = None
        self.ret = None
        #self.thread_event = mulproc.Event()
        self.thread_event = threading.Event()

    def tail_f(self, thread_event=None, path=None, filter=None):

        #default filter pattern: 'TRACE'
        pattern = '( TRACE: )'

        interface = filter.get('interface', None)
        proto = filter.get('proto',None)
        hostip = filter.get('hostip', None)
        if interface:
            pattern += '(?=.*%s )' % (interface)
        if proto:
            pattern += '(?=.* PROTO=%s )' % (proto)
        if hostip:
            pattern += '(?=.*=%s)' % (hostip)
        pattern = '(%s)' % pattern
        istrace = re.compile(pattern)

        #max save line 2000
        max_save_count = 2000
        #max time out 2000*0.5s
        count = 2000

        ret = []
        with open(path, 'r') as f:
            f.seek(0, 2)
            while count and max_save_count:
                #print "child stop:%s" %  thread_event.is_set()

                if thread_event.is_set():
                    self.ret = ret
                    #if pipe:
                    #    pipe.send(ret)
                    #    del ret[:]
                    break
                pos = f.tell()
                line = f.readline()
                if not line:
                    count = count - 1
                    time.sleep(0.5)
                    f.seek(pos)
                else:
                    #print line,istrace.search(line)
                    if istrace.search(line):
                        max_save_count = max_save_count - 1
                        ret.append(line)

            self.ret = ret
        return ret


    def thread_startup(self, path, filter):

        if not path:
            print('cannot find "path" in Tailf.sublime-settings.')
            return


        if self.thread is not None and self.thread.is_alive():
            print('thread is already started.')
            return

        #self.pipe = mulproc.Pipe()
        #self.thread = mulproc.Process(target=self.tail_f, args=(self.pipe[0], self.thread_event, path, filter))
        self.thread = threading.Thread(target=self.tail_f, args=(self.thread_event, path, filter))
        self.thread.start()


    def thread_stop(self):
        if self.thread is not None and self.thread.is_alive():
            self.thread_event.set()
            self.thread.join()
            return self.ret



    def thread_status(self):
        print self.thread.ident, self.thread

"""
def main():
    r = CollectLog()

    path = '/var/log/kern.log'
    filter = {
            'interface':'qbrebcf0a40-19',
            'proto':'UDP',
            'hostip':'192.168.111.15',
    }
    r.thread_startup(path, filter)

    count = 30
    while count:
        print "thread:", r.thread
        time.sleep(0.5)
        count = count -1

    r.thread_status()
    print r.thread_stop()

main()
"""
