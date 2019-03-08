#!/usr/bin/python

import dns.zone
import dns.resolver
import dns.tsigkeyring
from hashlib import md5
from netaddr import IPNetwork, IPAddress
from os import environ, path
from re import sub

def md5File(fileName):
  md5Hash = md5(environ["salt"])
  with open(fileName, "rb") as source:
    for chunk in iter(lambda: source.read(4096), b""):
      md5Hash.update(chunk)
  return md5Hash.hexdigest()

dir = path.dirname(path.realpath(__file__))
reverseZoneName = "168.192.in-addr.arpa"
reverseZoneFile = dir + "/db." + reverseZoneName
forwardZoneFile = dir + "/db.seenothing.net"
templateZoneFile = dir + "/.db.template"

# Compare hash of zone and remote
dnsResolver = dns.resolver.Resolver()
dnsResolver.nameservers=["69.125.235.157", "168.235.68.77", "52.201.141.242"]
keyring = dns.tsigkeyring.from_text({environ["tsigName"]:environ["tsigKey"]})
dnsResolver.use_tsig(keyring, keyname=environ["tsigName"])
remoteHash = dnsResolver.query(reverseZoneName, "TXT")[0].to_text()
fileHash = md5File(forwardZoneFile)
serial = dnsResolver.query(reverseZoneName, "SOA")[0].serial
if remoteHash != '"' + fileHash + '"':
  serial += 1

# Build dict of records
entries = []
forwardZone = dns.zone.from_file(forwardZoneFile)
for (name, ttl, rdata) in filter(lambda x: IPAddress(x[2].to_text()) in IPNetwork("192.168.0.0/16"), forwardZone.iterate_rdatas("A")):
  entry = {
    "thirdOctet": rdata.to_text().split(".")[2],
    "fourthOctet": rdata.to_text().split(".")[3],
    "name": name.to_text()
  }
  entries.append(entry)

# Write to file
with open(templateZoneFile, "r") as source:
  lines = source.readlines()
with open(reverseZoneFile, "w+") as source:
  for line in lines:
    line = sub(r"<SERIAL>", str(serial), line)
    line = sub(r"<DOMAIN>", reverseZoneName, line)
    source.write(line)
with open(reverseZoneFile, "a") as source:
  source.write("@\t\t\t\tIN TXT\t\t" + fileHash + "\n")
  source.write("\n;\n; PTR records\n; ------------------------------X---------------X-----\n")
  for i in sorted(entries, key=lambda x: (int(x["thirdOctet"]), int(x["fourthOctet"]))):
    source.write(i["fourthOctet"] + "." + i["thirdOctet"] + "\t\t\t\tIN PTR\t\t" + i["name"] + ".seenothing.net.\n")
