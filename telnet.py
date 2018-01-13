from telnetlib import Telnet
import time

def main():
    tn = Telnet()
    tn.open('10.100.218.8', 23, 3)

    ret = tn.read_until('username:')
    tn.write('admin' + '\n')

    ret = tn.read_until('password:')
    print ret
    ret = tn.write('admin' + '\n')

    ret = tn.read_until('>')
    print ret
    tn.write('show vlan')

    time.sleep(2)
    ret = tn.read_very_eager()
    print ret

    tn.close()


main()


