import argparse
import sys
from collections import defaultdict
import json
from libnmap.parser import NmapParser
from libnmap.objects.report import NmapReport
from get_port_services import get_scripts

gvar = None

def arguments():
    gvar
    parser = argparse.ArgumentParser()
    parser.add_argument('infile', nargs="?", type=argparse.FileType("r"), default=sys.stdin)
    parser.add_argument('outfile', nargs="?", type=argparse.FileType("w"), default=sys.stdout)
    return parser.parse_args()

def open_ports(report):
    ports = defaultdict(list)
    for host in report.hosts:
        for service in host.services:
            ports[host.address].append(service.port)
    return dict(ports)

def main():
    print(f"Reading input from {ARGS.infile.name}")
    nmap_report = NmapParser.parse_fromstring(ARGS.infile.read())
    print(f"Writing output to {ARGS.outfile.name}")
    ports = open_ports(nmap_report)
    print(json.dumps(ports, indent=2), file=ARGS.outfile)
    parser.append()
    gvar

    get_scripts()

if __name__ == "__main__":
    ARGS = arguments()
    main()


















































































































































































































































































































































































































































    some rando thing that'll break your code