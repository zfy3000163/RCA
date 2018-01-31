#!/usr/bin/env python
# -*- coding: utf-8 -*-

import signal
import ctypes
import random
import sys
import ctypes.util

import iptc


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


    def delete_trace_rule(self, mark_num=None):
        args_chain = ['OUTPUT','PREROUTING']

        if not iptc.is_table_available(iptc.Table.RAW):
            raise ValueError("table raw does not exist")

        table = iptc.Table("raw")

        rules = []
        for i in args_chain:
            chain = iptc.Chain(table, i)
            if len(chain.rules) != 0:
                count = len(chain.rules)-1
                while (count > 0):
                    cur_rule = chain.rules[count]

                    target_name = cur_rule.target.name
                    if target_name == 'MARK':
                        target_mark = cur_rule.target.get_all_parameters().get('set-xmark', None)
                        if target_mark and target_mark[0].split('/')[0] in mark_num:
                            print len(chain.rules), cur_rule
                            chain.delete_rule(cur_rule)

                    matches = cur_rule.matches
                    for matche in matches:
                        if matche.name == 'mark':
                            matche_mark = matche.get_all_parameters().get('mark', None)
                            if matche_mark and matche_mark[0] in mark_num:
                                print len(chain.rules), cur_rule
                                chain.delete_rule(cur_rule)


                    count -= 1;


    def insert_trace_rule(self, bpf=None, iface=None, clear_chain=False):

        args_chain = ['OUTPUT','PREROUTING']
        args_clear_chain = clear_chain
        args_bpf = bpf
        args_iface = iface
        args_xmark_mask = '0x800001ff'

        if not iptc.is_table_available(iptc.Table.RAW):
            raise ValueError("table raw does not exist")

        table = iptc.Table("raw")

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
            else:
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

        return record_marks


if __name__ == '__main__':
    try:
        iptc_opt = IptcOpt()
        mark = iptc_opt.insert_trace_rule(None, None, True)
    except ValueError:
        print "Args Error"

