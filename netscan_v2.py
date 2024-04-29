from __init__ import *
import socket
import struct
import ipaddress
import json
import csv
import subprocess
import platform
import concurrent.futures

class NetScanner:
    def __init__(self):
        self.ip_range = []
        self.alive_devices = []
        self.fqdns = {}

    def portscan(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, int(port)))
        if result == 0:
            self.alive_devices.append(ip)
            print(ip, f' port {port} is open.')
            netscan_logger.logger.info(f'{ip} port {port} is open.')
        sock.close()

    def pingscan(self, ip):
        ping_str = '-n 2' if platform.system().lower() == 'windows' else '-c 2'
        need_sh = platform.system().lower() != 'windows'
        args = 'ping ' + ' ' + ping_str + ' ' + ip
        # Ping
        if subprocess.call(args, shell=need_sh) == 0:
            self.alive_devices.append(ip)

    def ips(self, start, end):
        start = struct.unpack('>I', socket.inet_aton(start))[0]
        end = struct.unpack('>I', socket.inet_aton(end))[0]
        return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)]

    def nslook(self):
        for i in self.alive_devices:
            try:
                p = (socket.getnameinfo((i, 0), socket.NI_NAMEREQD))
                self.fqdns[i] = p[0]
            except Exception:
                self.fqdns[i] = 'NO DNS RECORD'

    def scan_worker(self, func, ips, *args):
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(func, ips, *args)

    def main(self, argv):
        file = None
        networks = []
        network = ''
        port = '22'
        try:
            opts, args = getopt.getopt(argv[1:], 'n:f:p:hv', ['help', 'version', 'network=', 'file-path=', 'port='])
        except getopt.GetoptError as e:
            self.error_reporter(e)
            sys.exit(2)

        for opt, arg in opts:
            if opt in ('-h', '--help'):
                self.help()
                sys.exit()
            elif opt in ('-v', '--version'):
                print('Version', version)
                sys.exit()
            elif opt in ('-n', '--network'):
                network = arg
                networks = network.split(',')
            elif opt in ('-f', '--file-path'):
                file = arg
            elif opt in ('-p', '--port'):
                port = arg
            else:
                self.error_reporter(opt)
                sys.exit()

        if any((not network, not file)):
            self.help()
            print('\n' + '\033[91m' + 'ERROR: Mandatory parameter is missing.' + '\033[0m' + '\n')
            netscan_logger.logger.error('Mandatory parameters are missing.')
            sys.exit()

        # find out ip ranges
        for n in networks:
            ip_ranges = ipaddress.ip_network(str(n))
            for ip in ip_ranges:
                self.ip_range.append(str(ip))

        print(f'{networks} are going to be scanned.')
        netscan_logger.logger.info(f'{networks} are going to be scanned.')

        # input('Press Enter to Continue...')
        if port == 'icmp':
            self.scan_worker(self.pingscan, self.ip_range)
        else:
            self.scan_worker(self.portscan, self.ip_range, port)

        print(f"{len(self.ip_range)} IPs scanned.")
        netscan_logger.logger.info(f"{len(self.ip_range)} IPs scanned.")

        self.nslook()

        hosts = self.fqdns

        header = ['IP-Address', 'Hostname']

        try:
            with open(file, 'w', encoding='UTF8', newline='') as f:
                if '.json' in file:
                    json.dump(hosts, f, indent=2)
                elif '.csv' in file:
                    writer = csv.DictWriter(f, fieldnames=header)
                    writer.writeheader()
                    for key in hosts.keys():
                        f.write('%s,%s\n' % (key, hosts[key]))
                elif '.txt' in file:
                    for key in hosts.keys():
                        f.write('%s     %s\n' % (key, hosts[key]))
                else:
                    print('\n' + '\033[91m' + 'ERROR: Unsupported file extension.' + '\033[0m' + '\n')
                    netscan_logger.logger.error('Unsupported file extension!')
            netscan_logger.logger.info(f'List of hosts inclusive DNS-Name stored in {file}')

        except IOError:
            print("\n" + "\033[91m" + f"ERROR: Occurred while opening file: {file}" + "\033[0m" + "\n")
            netscan_logger.logger.error('Error occurred while exporting to file: {0}'.format(file))

        print(f'\nFound {len(hosts)} IP(s) with port 22 open:', hosts, '\n')
        netscan_logger.logger.info(f'Found {len(hosts)} IP(s) with port 22 open: {hosts}')

    # Error reporter
    def error_reporter(self, arg0):
        self.help()
        print(((('\n' + '\033[31m' + f'ERROR: Parameter {arg0}') + '\033[0m') + '\n'))
        netscan_logger.logger.error(f'Parameter {arg0}')

    @staticmethod
    def help():
        print(r'''
        Scans the specified network to find and list alive nodes.
        
        Syntax:  /usr/bin/python netscan.py [-n Network -p Port -f FilePath ] ...
        
        example: /usr/bin/python netscan.py -n 192.168.1.0/24 -p 22 -f /etc/output.json
                 /usr/bin/python netscan.py -n 192.168.1.16/30,192.168.2.2/32 -p icmp -f /etc/output.json
        
        args:
        -h --help           Help.
        -v --version        Shows version.        
        -n --network        Network(S) to scan.
        -p --port           Port to check. (or icmp for Ping)
        -f --file-path      File path containing file name to save the output.
                            You can write the output in .csv, .txt or .json file formats.
        
        © 2023 Hamid Sadeghian
        ''')


if __name__ == '__main__':
    netscan_logger = LoggerConfig(os.path.basename(__file__).split(".")[0])
    netscan_logger.logger.info(f'{__file__} started.')
    scanner = NetScanner()
    scanner.main(sys.argv)
    netscan_logger.logger.info(f'{__file__} ended.')
