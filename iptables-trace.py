#!/usr/bin/python

# pip install python-iptables
import socket
import select
import signal
import ctypes
import struct

import iptc
from libnetfilter.log import nflog_handle
from libnetfilter.netlink import nf_log


# monkey patch as the std version breaks with inverted values
def _get_all_parameters(self):
	import shlex
	params = {}
	ip = self.rule.get_ip()
	buf = self._get_saved_buf(ip)
	if buf is None:
		return params
	res = shlex.split(buf)
	res.reverse()
	values = []
	key = None
	while len(res) > 0:
		x = res.pop()
		if x.startswith('--'): # This is a parameter name.
			values.append(x[2:])
			key = " ".join(values)
			params[key] = []
			continue
		if key:
			params[key].append(x) # This is a parameter value.
		else:   
			values.append(x)
	return params

iptc.ip4tc.IPTCModule.get_all_parameters = _get_all_parameters


running = True
def signal_handler(signal, frame):
	global running
	running = False
signal.signal(signal.SIGINT, signal_handler)

def nfbpf_compile(pattern):
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

	def pcap_compile_nopcap_errcheck(result, function, args):
		if result == -1:
			raise ValueError(args)

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


def format_parameters(args):
	r = {}
	for k,v in args.items():
		if type(v) == str:
			r[k] = v
		else:
			r[k] = " ".join(v)
	return str(r)

def trace_cb(gh, nfmsg, nfa, data):
	prefix = nfa.prefix
	if not prefix.startswith('TRACE: '):
		return 0

	# chainname may have :, therefore split and re-create chainname
	p = prefix[7:].split(":")
	tablename,chainname,type,rulenum = [p[0], ':'.join(p[1:-2]), p[-2], p[-1]]

	table = iptc.Table(tablename)
	chain = iptc.Chain(table, chainname)
	pkt = nfa.payload

	if tablename == 'raw' and chainname in ('PREROUTING','OUTPUT'):
		print(nf_log(pkt, nfa.indev, nfa.outdev))

	r = "\t{} {} ".format(tablename,chainname)
	if type == 'policy':
		x = chain.get_policy().name
		if x == 'ACCEPT':
			x = bcolors.ok(x)
		else:
			x = bcolors.fail(x)
	elif type == 'rule':
		r += "(#{r}) ".format(r=rulenum.strip())
		rule = chain.rules[int(rulenum)-1]
		x = "{r.protocol} {r.src} -> {r.dst} ".format(r=rule)
		for m in rule.matches:
			if m.name == 'comment':
				r += "/* {} */".format(m.get_all_parameters()['comment'][0])
			else:
				x += "{}:{} ".format(m.name, format_parameters(m.get_all_parameters()))

		tp = rule.target.get_all_parameters()
		if len(tp) > 0:
			tp = format_parameters(tp)
		else:
			tp = ""

		if rule.target.name == 'ACCEPT':
			targetname = bcolors.ok(rule.target.name)
		elif rule.target.name in ('REJECT','DROP'):
			targetname = bcolors.fail(rule.target.name)
		else:
			targetname = bcolors.next(rule.target.name)
		x += "\n\t\t=> {} {}".format(targetname, tp)
	elif type == 'return':
		# unconditional rule having the default policy of the calling chain get named "return"
		# net/ipv4/netfilter/ip_tables.c
		# get_chainname_rulenum
		try:
				r += "(#{r}) ".format(r=rulenum.strip())
				rule = chain.rules[int(rulenum)-1]
				if rule.target.name == 'ACCEPT':
						targetname = bcolors.ok(rule.target.name)
				elif rule.target.name in ('REJECT','DROP'):
						targetname = bcolors.fail(rule.target.name)
				else:
						targetname = bcolors.next(rule.target.name)
				x = "=> {}".format(targetname)
		except Exception as e:
				x = "return"

	r += "NFMARK=0x{:x} (0x{:x})".format(nfa.nfmark & data, nfa.nfmark)

	print("{}\n\t\t{}".format(r,x))
	return 0

def safe_decode_utf8(s):
    #if six.PY3 and isinstance(s, bytes):
    if isinstance(s, str):
	return s.decode('utf-8', 'surrogateescape')
    return s

import pdb
def main():
	global running
	import argparse
	import random

	parser = argparse.ArgumentParser(description='iptables-trace')

	parser.add_argument('--clear-chain', action='store_true', default=False, help="delete all rules in the chain")
	parser.add_argument('--chain','-c', type=str, nargs='*', choices=['OUTPUT','PREROUTING'], default=["OUTPUT",'PREROUTING'], help='chain')
	parser.add_argument('--source','-s', type=str, action='store', default=None, help='source')
	parser.add_argument('--destination','-d', type=str, action='store', default=None, help='destination')
	parser.add_argument('--protocol', '-p', type=str, action='store', default=None, help='protocol')
	parser.add_argument('--iface', '-i', type=str, action='store', default=None, help='iface')
	parser.add_argument('--bpf',type=str, default=None, action='store')
	parser.add_argument('--xmark-mask', '-M', type=str, action='store', default="0x800001ff", help='mark mask (bits to use) default is not to use lower 9 bits and the highest')
	parser.add_argument("--limit", action='store_true', default=False, help="limit rule matches to 1/second")

	args = parser.parse_args()

	if not iptc.is_table_available(iptc.Table.RAW):
		raise ValueError("table raw does not exist")
	table = iptc.Table("raw")

	rules = []
	for i in args.chain:
		chain = iptc.Chain(table, i)

		if args.clear_chain == True and len(chain.rules) != 0:
                    count = len(chain.rules)-1
                    while (count > 0):
                        name = chain.rules[count].target.name
                        if name in ['MARK','TRACE']:
                            j = chain.rules[count]
                            print len(chain.rules), j
                            chain.delete_rule(j)
                        count -= 1;

		mark = iptc.Rule()
		if args.protocol:
			mark.protocol = args.protocol
		if args.source:
			mark.src = args.source
		if args.destination:
			mark.dst = args.destination

		if args.bpf:
			bpf = mark.create_match("bpf")
			bpf.bytecode = nfbpf_compile(args.bpf)
			comment = mark.create_match("comment")
			comment.comment = 'bpf: "{}"'.format(args.bpf)
		if args.limit:
			limit = mark.create_match('limit')
			limit.limit = "1/second"
			limit.limit_burst = "1"

		if i == 'PREROUTING':
			if args.iface:
				mark.in_interface = args.iface
		elif i == 'OUTPUT':
			if args.iface:
				mark.out_interface = args.iface

		mark.target = iptc.Target(mark, "MARK")
		m = 0
		while m == 0:
			_m = random.randint(0,2**32-1)
			_m &= ~int(args.xmark_mask, 16)
			m = "0x{:x}".format(_m)
		mark.target.set_mark = m
		chain.append_rule(mark)
		rules.append((chain,mark))

		trace = iptc.Rule()
		match = trace.create_match("mark")
		match.mark = "{}/0x{:x}".format(m,0xffffffff & ~int(args.xmark_mask, 16))
		trace.target = iptc.Target(trace, "TRACE")
		chain.append_rule(trace)
		rules.append((chain,trace))

	n = nflog_handle.open()
	r = n.unbind_pf(socket.AF_INET)
	r = n.bind_pf(socket.AF_INET)
	qh = n.bind_group(0)
	qh.set_mode(0x02, 0xffff)

	qh.callback_register(trace_cb, int(args.xmark_mask, 16));

	fd = n.fd

	while running:
		try:
			r,w,x = select.select([fd],[],[],1.)
			if len(r) == 0:
				# timeout
#				print("timeout")
				continue
			if fd in r:
				n.handle_io()
		except:
			pass

	for chain,rule in rules:
		chain.delete_rule(rule)

if __name__ == '__main__':
	main()

