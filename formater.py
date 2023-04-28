#!/home/kali/scripts/nmap_parser/venv/bin/python

import sys, json
from tabulate import tabulate
import argparse
from pprint import pformat
from collections import defaultdict
from prettytable import PrettyTable, DOUBLE_BORDER, ALL
from textwrap import TextWrapper

def arguments():
    parser = argparse.ArgumentParser(description="Format JSON data for output or to send to notify")
    parser.add_argument('infile', nargs="?", type=argparse.FileType("r"), default=sys.stdin, help="Specify Input file, default stdin")
    parser.add_argument('outfile', nargs="?", type=argparse.FileType("w"), default=sys.stdout, help="Specify Output file, default stdout")
    return parser.parse_args()

def format_script_data(ip: str, port: str, script_data: dict) -> list:
    # return pformat(script_data)

    wraper = TextWrapper()
    results = []
    # ids = []
    # elements = []
    # outputs = []
    for result in script_data:
        _id = result['id']
        # elems = "\n".join([f"{key}: {val}" for key, val in result['elements'].items()])
        results.append([ip, port, _id, "\n".join(wraper.wrap(result["output"]))])
        # outputs.append(result["output"])
        # ids.append(_id)
        # elements.append(elems)
    # ids = "\n".join(ids)
    # elements = "\n".join(elements)
    # outputs = "".join(outputs)
    
    # return [ids, elements, outputs]
    return results


def print_table(rows, headers) -> PrettyTable:
    table = PrettyTable(field_names=headers)
    for row in rows:
        table.add_row(row)
    table.align = "l"
    table.set_style(DOUBLE_BORDER)
    table.hrules=ALL
    return table


def main():
    args = arguments()
    with args.infile as infile, args.outfile as outfile:
        rows = []
        data = json.loads(infile.read())

        script_results = []
        for ip, ip_info in data.items():
            if not ip_info:
                port = "N/A"
                proto = "N/A"
                reason = "N/A"
                service = "N/A"
                product = "N/A"
                version = "N/A"
                ostype = "N/A"
                rows.append((ip, port, proto, reason, service, product, version, ostype))
                continue

            # port_data = defaultdict(list)
            for port, service_info in ip_info.items():
                proto = service_info.get('protocol', "N/A")
                reason = service_info.get('reason', "N/A")
                service = service_info.get('service', dict()).get('name', "N/A")
                product = service_info.get('service', dict()).get('product', "N/A")
                version = service_info.get('service', dict()).get('version', "N/A")
                ostype = service_info.get('service', dict()).get('ostype', "N/A")
                
                # port_data['port'].append(port)
                # port_data["proto"].append(service_info.get('protocol', "N/A"))
                # port_data["reason"].append(service_info.get('reason', "N/A"))
                # port_data["service"].append(service_info.get('service', dict()).get('name', "N/A"))
                # port_data["product"].append(service_info.get('service', dict()).get('product', "N/A"))
                # port_data["version"].append(service_info.get('service', dict()).get('version', "N/A"))
                # port_data["ostype"].append(service_info.get('service', dict()).get('ostype', "N/A"))
                # scripts = json.dumps(service_info['scripts_results'])
                scripts = format_script_data(ip, port, service_info['scripts_results'])
                script_results.extend(scripts)
            # port = "\n".join(port_data['port'])
            # proto = "\n".join(port_data["proto"])
            # reason = "\n".join(port_data["reason"])
            # service = "\n".join(port_data["service"])
            # product = "\n".join(port_data["product"])
            # version = "\n".join(port_data["version"])
            # ostype = "\n".join(port_data["ostype"])
                rows.append((ip, port, proto, reason, service, product, version, ostype))

        print(print_table(rows, headers=["Host", "Port(s)", "Proto", "Reason", "Service", "Product", "Version", "OsType"]), file=outfile)
        # print()
        # print(tabulate(script_results, headers=, tablefmt="pretty"), file=outfile)
        print(print_table(script_results, headers=["IP", "Port", "ID", "OUTPUT"]), file=outfile)

if __name__ == "__main__":
    main()