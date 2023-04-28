#!/home/kali/scripts/nmap_parser/venv/bin/python

from get_open_ports import arguments
import argparse
import sys
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapReport
import json
from typing import List
from collections import defaultdict
import concurrent.futures as cf

def arguments():
    parser = argparse.ArgumentParser(description="Take Nmap XML Output and parse open ports for each host. Returns JSON")
    parser.add_argument('infile', nargs="?", type=argparse.FileType("r"), default=sys.stdin, help="Specify Input file, default stdin")
    parser.add_argument('outfile', nargs="?", type=argparse.FileType("w"), default=sys.stdout, help="Specify Output file, default stdout")
    return parser.parse_args()

SCRIPT_MAPPING = {
    "21": '--script ftp-*',
    "22": '--script "ssh2-enum-algos or ssh-hostkey or ssh-auth-methods" --script-args ssh_hostkey=full --script-args="ssh.user=root"',
    "53": '--script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport"',
    "80": '--script "banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)"',
    "135":'--script "msrpc-enum"',
    "139": '--script "safe or smb-enum-* or smb-vuln*"',
    "443": '--script "banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)"',
    "445": '--script "safe or smb-enum-* or smb-vuln*"',
    "2049": '--script=nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse',
    "8080": '--script "banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)"',
}
def get_scripts(port: str) -> str:
    return SCRIPT_MAPPING.get(port, "")


def run_scan(host:str, ports: List[int], scripts: set) -> NmapProcess:
    scripts = ' '.join(scripts) or "--script default"
    ports = ','.join(map(str, ports))
    scan = NmapProcess(targets=host, options=f"-sV {scripts} -p{ports}")
    print(f"running {scan.command}", file=sys.stderr)
    scan.run()
    return scan

def main():
    args = arguments()

    with args.infile as infile, args.outfile as outfile:
        # expect json string
        inp = json.loads(infile.read())
        def process(host, ports):
            scripts = set()
            for port in ports:
                s = get_scripts(port)
                if s:
                    scripts.add(s)
            service_scan = run_scan(host, ports, scripts)
            return NmapParser.parse(service_scan.stdout)

        with cf.ThreadPoolExecutor() as executor:
            threads = {executor.submit(process, host, ports): host for host, ports in inp.items() if ports}
                
            for future in cf.as_completed(threads):
                host = threads[future]
                service_scan_results = future.result()
        # for k,v in inp.items():
        #     for host, ports, in inp.items():
                # service_scan_results = process(host, ports)
                if not service_scan_results.hosts_up:
                    print(f"{host} not up...", file=sys.stderr)
                    continue
                inp[host] = {}
                for service in service_scan_results.hosts[0].services:
                    port_info = {
                        "banner": service.banner_dict,
                        "protocol": service.protocol,
                        "reason": service.reason,
                        "service": service.service_dict,
                        "scripts_results": service.scripts_results,
                    }
                    inp[host][service.port] = port_info
                    
        print(f"Writing to {outfile.name}", file=sys.stderr)
        print(json.dumps(inp, indent=2), file=outfile)

if __name__ == "__main__":
    main()