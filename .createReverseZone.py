#!/usr/bin/python

# update config script to limit allow-query to reverse zone

import dns.zone
import dns.resolver
import dns.tsigkeyring
import re
import os

dir = os.path.dirname(os.path.realpath(__file__))

reverseDNS = dns.resolver.Resolver()
reverseDNS.nameservers=["69.125.235.157", "168.235.68.77", "52.201.141.242"]
keyring = dns.tsigkeyring.from_text({"query-key":"kVhxznJq5fgHn961Am7EZw=="})
reverseDNS.use_tsig(keyring, keyname="query-key")
serial = reverseDNS.query("168.192.in-addr.arpa", "SOA")[0].serial + 1

zoneFileName = "db.168.192.in-addr.arpa"

entries = []
zone = dns.zone.from_file(dir + '/db.seenothing.net')
for (name, ttl, rdata) in zone.iterate_rdatas('A'):
  if re.match(r"^192.168.", rdata.to_text()):
    entry = {
      "thirdOctet": rdata.to_text().split(".")[2],
      "fourthOctet": rdata.to_text().split(".")[3],
      "name": name.to_text()
    }
    entries.append(entry)

with open(dir + "/.db.template", "r") as sources:
  lines = sources.readlines()
with open(dir + "/" + zoneFileName, "w+") as sources:
  for line in lines:
    line = re.sub(r"<SERIAL>", str(serial), line)
    line = re.sub(r"<DOMAIN>", zoneFileName.partition(".")[2], line)
    sources.write(line)

sources = open(dir + "/" + zoneFileName, "a")
sources.write("\n;\n; PTR records\n; ------------------------------X---------------X-----\n")
for i in sorted(entries, key=lambda k: (int(k["thirdOctet"]), int(k["fourthOctet"]))):
  sources.write(i["fourthOctet"] + "." + i["thirdOctet"] + "\t\t\t\tIN PTR\t\t" + i["name"] + "\n")
