# Plunderer

## Intro
Plunderer is a simple subdomain takeover tool for identifying and hijacking subdomains/domains that once had Route53 hosted zones associated with them.

## Install
Installation is also simple, as this doesn't have many dependencies. You can install them with Pip:
`pip3 install -r requirements.txt`

If you want to make use of the hijacking functionality you will need awscli installed and configured with access keys that have Route53 hosted create/delete permissions:
`pip3 install awscli`

## Usage
Usage is pretty simple but changes based on mode. For example, to identify whether or not a single subdomain is vulnerable:
`./plunderer.py -m i -d isitvulnornot.google.com`

For a full list of options see below:

```
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain
  -m MODE, --mode MODE  Would you like to check if subdomains are vulnerable
                        to Route53 hijacking or hijack an identified
                        vulnerable domain? (Valid values: [i]dentify /
                        [h]ijack - default is i)
  -ns AWSNAMESERVER, --awsnameserver AWSNAMESERVER
                        Only for mode: hijack - provide the vulnerable domains
                        AWS nameserver(s), i.e. ns-170.awsdns-21.com or a
                        comma seperated list, like the output of the
                        identification function
  -iL INPUTLIST, --inputlist INPUTLIST
                        Read domains from a list file
  -o OUTFILE, --outfile OUTFILE
                        Write out list of vulnerable domains to a file
```
