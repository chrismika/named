#!/usr/bin/python

import dns.zone
import dns.resolver
import dns.tsigkeyring
import hashlib
from netaddr import IPNetwork, IPAddress
from os import environ, path
from re import sub

def md5(fname):
  hashMd5 = hashlib.md5()
  with open(fname, "rb") as f:
    for chunk in iter(lambda: f.read(4096), b""):
      hashMd5.update(chunk)
  return hashMd5.hexdigest()

dir = path.dirname(path.realpath(__file__))
zoneFile = "db.168.192.in-addr.arpa"

# Compare hash of zone and remote
dnsResolver = dns.resolver.Resolver()
dnsResolver.nameservers=["69.125.235.157", "168.235.68.77", "52.201.141.242"]
keyring = dns.tsigkeyring.from_text({environ["tsigName"]:environ["tsigKey"]})
dnsResolver.use_tsig(keyring, keyname=environ["tsigName"])
remoteHash = dnsResolver.query("168.192.in-addr.arpa", "TXT")[0].to_text()
fileHash = md5(dir + "/db.seenothing.net")
serial = dnsResolver.query("168.192.in-addr.arpa", "SOA")[0].serial
if remoteHash != '"' + fileHash + '"':
  serial += 1

# Build dict of records
entries = []
zone = dns.zone.from_file(dir + "/db.seenothing.net")
for (name, ttl, rdata) in filter(lambda x: IPAddress(x[2].to_text()) in IPNetwork("192.168.0.0/16"), zone.iterate_rdatas("A")):
    entry = {
      "thirdOctet": rdata.to_text().split(".")[2],
      "fourthOctet": rdata.to_text().split(".")[3],
      "name": name.to_text()
    }
    entries.append(entry)

# Write to file
with open(dir + "/.db.template", "r") as sources:
  lines = sources.readlines()
with open(dir + "/" + zoneFile, "w+") as sources:
  for line in lines:
    line = sub(r"<SERIAL>", str(serial), line)
    line = sub(r"<DOMAIN>", zoneFile.partition(".")[2], line)
    sources.write(line)
sources = open(dir + "/" + zoneFile, "a")
sources.write("@\t\t\t\tIN TXT\t\t" + fileHash + "\n")
sources.write("\n;\n; PTR records\n; ------------------------------X---------------X-----\n")
for i in sorted(entries, key=lambda k: (int(k["thirdOctet"]), int(k["fourthOctet"]))):
  sources.write(i["fourthOctet"] + "." + i["thirdOctet"] + "\t\t\t\tIN PTR\t\t" + i["name"] + ".seenothing.net.\n")
