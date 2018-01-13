
import time
import signal
import threading
import multiprocessing  as mulproc

_thread = None
_stop = False
_path = "/var/log/kern.log"

def signal_handler(signal, frame):
    global _stop
    _stop = True
    print "handle, _stop:", _stop

def tail_f(pipe, stop):
    global _stop, _path
    count = 2000
    ret = []
    with open(_path, 'r') as f:
        f.seek(0, 2)
        while count:
            count = count - 1
            print "child stop:%s" %  stop.is_set()

            if stop.is_set():
                if pipe:
                    pipe.send(ret)
                    del ret[:]
                break
            pos = f.tell()
            line = f.readline()
            if not line:
                time.sleep(0.5)
                f.seek(pos)
            else:
                #print line,
                ret.append(line)


class TailfStartCommand():

    def run(self, stop_thread):
        global _thread, _path

        if not _path:
            print('cannot find "path" in Tailf.sublime-settings.')
            return

        if _thread is not None and _thread.is_alive():
            print('thread is already started.')
            return

        pipe = mulproc.Pipe()
        _thread = mulproc.Process(target=tail_f, args=(pipe[0], stop_thread))
        #_thread = mulproc.threading.Thread(target=tail_f, args=(stop_thread,))
        #_thread.setDaemon(True)
        _thread.start()
        print('thread started.%s',_thread)
        return pipe

class TailfStopCommand():

    def run(self):
        global _thread, _stop
        if _thread is not None and _thread.is_alive():
            _stop = True
            _thread.join()
            print _thread
            if _thread.exitcode == 0:
                pass
            _thread = None
        print('thread stopped.')


class TailfStatusCommand():

    def run(self):
        global _thread
        print _thread

def main():
    signal.signal(signal.SIGINT, signal_handler)
    r = TailfStartCommand()
    stop_thread = False;
    child_thread_stop = mulproc.Event()
    pipe = r.run(child_thread_stop)

    global _thread, _stop
    while True:
        print "while, _stop:", _stop, _thread
        if _stop == True:
            if _thread is not None and _thread.is_alive():
                print "22222", _stop
                child_thread_stop.set()
                _thread.join()
                print _thread
                if _thread.exitcode == 0:
                    print "exit thread"
                    if pipe:
                        ret = pipe[1].recv()
                        print ret

                break
            else:
                break

        time.sleep(0.5)

main()
