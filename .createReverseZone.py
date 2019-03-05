#!/usr/bin/python

# update config script to limit allow-query to reverse zone

import dns.zone
import dns.ipv4
import dns.resolver
import dns.tsigkeyring
import re
from shutil import copyfile
import pprint

reverseDNS = dns.resolver.Resolver()
reverseDNS.nameservers=["69.125.235.157", "168.235.68.77", "52.201.141.242"]
keyring = dns.tsigkeyring.from_text({"query-key":"kVhxznJq5fgHn961Am7EZw=="})
reverseDNS.use_tsig(keyring, keyname="query-key")
serial = reverseDNS.query("168.192.in-addr.arpa", "SOA").rrset[0].serial
print serial



# below, the bottom two are equivalent, the [0] is the first response in a list, there's only one list member
resp = reverseDNS.query("168.192.in-addr.arpa", "SOA")
print resp.rrset[0].serial
type (resp.rrset[0].serial)
print hex(id(resp.rrset[0].serial))
print resp[0].serial
type (resp[0].serial)
try:
  print resp[1].serial
except Exception as e:
  print e
print hex(id(resp[0].serial))
resp = reverseDNS.query("seenothing.org", "MX")
print resp.rrset[0].preference
print resp.rrset[1].preference



print type(reverseDNS.query("168.192.in-addr.arpa", "SOA"))
print vars(reverseDNS.query("168.192.in-addr.arpa", "SOA"))
print "#####"
print type(reverseDNS.query("168.192.in-addr.arpa", "SOA").__class__)
pprint.pprint(reverseDNS.query("168.192.in-addr.arpa", "SOA")[0])
print "#####"
print type(reverseDNS.query("168.192.in-addr.arpa", "SOA")[0].serial)


# zoneFileName = "db.168.192.in-addr.arpa"
# copyfile(".db.template", zoneFileName)
# zoneFile = open(zoneFileName, "w")
# buffer = "\n;\n; PTR records\n; ------------------------------X---------------X-----\n"

# zone = dns.zone.from_file('db.seenothing.net')
# for (name, ttl, rdata) in zone.iterate_rdatas('A'):
#   if re.match(r"^192.168.", rdata.to_text()):
#    ip = rdata.to_text().split(".")
#    buffer += ip[3] + "." + ip[2] + "\t\t\t\tIN PTR\t\t" + name.to_text() + "\n"
# print buffer
