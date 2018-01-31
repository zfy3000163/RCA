#!/usr/bin/env python
# -*- coding: utf-8 -*-

import signal
import ctypes
import random
import sys
import re 
import ctypes.util

import iptc


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    @staticmethod
    def ok(data):
        return bcolors.OKGREEN + data + bcolors.ENDC
    @staticmethod
    def fail(data):
        return bcolors.FAIL + data + bcolors.ENDC
    @staticmethod
    def next(data):
        return bcolors.OKBLUE + data + bcolors.ENDC



class IptcOpt():
    def __init__(self):
        pass

    def nfbpf_compile(self, pattern):
        import ctypes.util

        class _bpf_insn(ctypes.Structure):
            _fields_ = [
                    ("code",ctypes.c_short),
                    ("jt",ctypes.c_uint8),
                    ("jf",ctypes.c_uint8),
                    ("k",ctypes.c_uint32)
            ]

        class bpf_program(ctypes.Structure):
            _fields_ = [
                    ("bf_len", ctypes.c_int),
                    ("bf_insns", ctypes.POINTER(_bpf_insn))
            ]

        _LP_bpf_program = ctypes.POINTER(bpf_program)

        libpcap = ctypes.CDLL(ctypes.util.find_library("pcap"))

        def pcap_compile_nopcap_errcheck(result, function, pattern):
            if result == -1:
                raise ValueError(pattern)

        # int pcap_compile_nopcap(int snaplen, int linktype, struct bpf_program *fp, char *str, int optimize, bpf_uint32 netmask);
        libpcap.pcap_compile_nopcap.restype = ctypes.c_int
        libpcap.pcap_compile_nopcap.argtypes = [ctypes.c_int, ctypes.c_int, _LP_bpf_program, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
        libpcap.pcap_compile_nopcap.errcheck = pcap_compile_nopcap_errcheck


        buf = ctypes.c_char_p(pattern)
        optimize = ctypes.c_int(1)
        mask = ctypes.c_uint32(0xffffffff)
        program = bpf_program()
        DLT_RAW = 12
        libpcap.pcap_compile_nopcap(40, DLT_RAW, ctypes.byref(program), buf, optimize, mask)
        if program.bf_len > 64: # XT_BPF_MAX_NUM_INSTR
            raise ValueError("bpf: number of instructions exceeds maximum")
        r = "{:d}, ".format(program.bf_len)
        r += ", ".join(["{i.code} {i.jt} {i.jf} {i.k}".format(i=program.bf_insns[i]) for i in range(program.bf_len)])
        return r


    def delete_trace_rule(self, marknum_list=None, comment_pattern=None):
        args_chain = ['OUTPUT','PREROUTING']

        if not iptc.is_table_available(iptc.Table.RAW):
            raise ValueError("table raw does not exist")

        table = iptc.Table("raw")
        table.refresh()

        def scan_rule(chain=None):
            wait_delete = []
            if len(chain.rules) != 0:
                for cur_rule in chain.rules:
                    del_rule_flag = 0
                    target_name = cur_rule.target.name
                    if target_name == 'MARK':
                        target_mark = cur_rule.target.get_all_parameters().get('set-xmark', None)
                        if target_mark and target_mark[0].split('/')[0] in marknum_list:
                            del_rule_flag = 1
                            wait_delete.append(cur_rule)

                    matches = cur_rule.matches
                    for matche in matches:
                        if matche.name == 'mark':
                            matche_mark = matche.get_all_parameters().get('mark', None)
                            if matche_mark and matche_mark[0] in marknum_list:
                                wait_delete.append(cur_rule)

                        if not del_rule_flag and matche.name == 'comment':
                            matche_comment = matche.get_all_parameters().get('comment', None)
                            if matche_comment and comment_pattern and matche_comment[0] in comment_pattern:
                                #if del the --mark rule,then must del with this mark's  TRACE rule
                                marknum_list.append(target_mark[0].split('/')[0])
                                wait_delete.append(cur_rule)
            return wait_delete

        for i in args_chain:
            chain = iptc.Chain(table, i)
            wait_delete = scan_rule(chain)
            for rule in wait_delete:
                chain.delete_rule(rule)


    def insert_trace_rule(self, bpf=None, iface=None, clear_chain=False):

        args_chain = ['OUTPUT','PREROUTING']
        args_clear_chain = clear_chain
        args_bpf = bpf
        args_iface = iface
        args_xmark_mask = '0x800001ff'

        if not iptc.is_table_available(iptc.Table.RAW):
            raise ValueError("table raw does not exist")

        table = iptc.Table("raw")
        table.refresh()

        record_marks = []
        rules = []
        for i in args_chain:
            chain = iptc.Chain(table, i)
            if args_clear_chain == True and len(chain.rules) != 0:
                count = len(chain.rules)-1
                while (count > 0):
                    name = chain.rules[count].target.name
                    if name in ['MARK','TRACE']:
                        j = chain.rules[count]
                        print len(chain.rules), j
                        chain.delete_rule(j)
                    count -= 1;

            mark = iptc.Rule()
            if args_bpf:
                bpf = mark.create_match("bpf")
                bpf.bytecode = self.nfbpf_compile(args_bpf)
                comment = mark.create_match("comment")
                comment.comment = 'bpf: "{}"'.format(args_bpf)

            if i == 'PREROUTING':
                if args_iface:
                    mark.in_interface = args_iface
            elif i == 'OUTPUT':
                if args_iface:
                    mark.out_interface = args_iface

            mark.target = iptc.Target(mark, "MARK")
            m = 0
            while m == 0:
                _m = random.randint(0,2**32-1)
                _m &= ~int(args_xmark_mask, 16)
                m = "0x{:x}".format(_m)

            mark.target.set_mark = m
            chain.append_rule(mark)
            rules.append((chain,mark))

            trace = iptc.Rule()
            match = trace.create_match("mark")
            #match.mark = "{}/0x{:x}".format(m,0xffffffff & ~int(args_xmark_mask, 16))
            match.mark = "{}/0x{:x}".format(m,0xffffffff)
            trace.target = iptc.Target(trace, "TRACE")
            chain.append_rule(trace)
            rules.append((chain,trace))

            record_marks.append(m)

        return record_marks, 'bpf: "{}"'.format(args_bpf)


    def format_parameters(self, args):
        r = {}
        for k,v in args.items():
            if type(v) == str:
                r[k] = v
            else:
                r[k] = " ".join(v)
        return str(r)

    def trace_packet(self, iface=None, data=None):
        temp_pkt = data

        split_square_brackets = re.compile('\[[^]]*] ' )
        split_array = split_square_brackets.split(temp_pkt)

        trace_data = split_array[1]

        if not trace_data.startswith('TRACE: '):
            return 0

        tmp = trace_data[7:].split(' ')
        prefix = tmp[0]
        pkt = tmp
        p = prefix.split(":")
        tablename,chainname,type,rulenum = [p[0], ':'.join(p[1:-2]), p[-2], p[-1]]

        table = iptc.Table(tablename)
        table.refresh()
        chain = iptc.Chain(table, chainname)
        print pkt

        result={'code':1, 'tablename':tablename, 'chainname':chainname, 'rulenum':rulenum.strip(), 'target':None, 'direction':None}
        r = "\t{} {} ".format(tablename,chainname)
        if type == 'policy':
            x = chain.get_policy().name
            if x == 'ACCEPT':
                result['code']=1
                result['target']=x
                x = bcolors.ok(x)
            else:
                result['code']=0
                result['target']=x
                x = bcolors.fail(x)
        elif type == 'rule':
            r += "(#{r}) ".format(r=rulenum.strip())
            rule = chain.rules[int(rulenum)-1]
            x = "{r.protocol} {r.src} -> {r.dst} ".format(r=rule)
            for m in rule.matches:
                if m.name == 'comment':
                    r += "/* {} */".format(m.get_all_parameters()['comment'][0])
                else:
                    x += "{}:{} ".format(m.name, self.format_parameters(m.get_all_parameters()))

            tp = rule.target.get_all_parameters()
            if len(tp) > 0:
                tp = self.format_parameters(tp)
            else:
                tp = ""

            if rule.target.name == 'ACCEPT':
                result['code']=1
                targetname = bcolors.ok(rule.target.name)
            elif rule.target.name in ('REJECT','DROP'):
                result['code']=0
                targetname = bcolors.fail(rule.target.name)
            else:
                result['code']=2
                targetname = bcolors.next(rule.target.name)
            x += "  => {} {}".format(targetname, tp)
            result['target']=rule.target.name
        elif type == 'return':
            # unconditional rule having the default policy of the calling chain get named "return"
            # net/ipv4/netfilter/ip_tables.c
            # get_chainname_rulenum
            try:
                r += "(#{r}) ".format(r=rulenum.strip())
                rule = chain.rules[int(rulenum)-1]
                if rule.target.name == 'ACCEPT':
                    result['code']=1
                    targetname = bcolors.ok(rule.target.name)
                elif rule.target.name in ('REJECT','DROP'):
                    result['code']=0
                    targetname = bcolors.fail(rule.target.name)
                else:
                    result['code']=2
                    targetname = bcolors.next(rule.target.name)

                x = "=> {}".format(targetname)
                result['target']=rule.target.name
            except Exception as e:
                result['code']=3
                result['target']='retrun'
                x = "return"

        if result['code'] == 0:
            pattern = '(( PHYSOUT=%s ))' % ('tap'+iface[3:])
            is_outdirection = re.compile(pattern)
            if is_outdirection.search(temp_pkt):
                result['direction']='ingress'
            else:
                result['direction']='egress'
        print("{} : {}".format(r,x))
        return result




"""
if __name__ == '__main__':
    try:
        iptc_opt = IptcOpt()
        mark, bpf = iptc_opt.insert_trace_rule(sys.argv[1], sys.argv[2], True if sys.argv[3]=='True' else False)

        if len(sys.argv) >= 5:
            if sys.argv[4] == 'del':
                iptc_opt.delete_trace_rule(mark, bpf)
    except ValueError:
        print "Args Error"
"""
