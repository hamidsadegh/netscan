import sys
import getopt
import socket, struct
from netaddr import *
from datetime import date
import json, csv
import subprocess, platform
import logging


today= date.today()
today_dot = today.strftime('%d.%m.%Y')

logging.basicConfig(filename='logs/log_%s' %today,
                    filemode='w+',
                    format='%(asctime)s %(levelname)s %(message)s',           
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG)

version = '1.0'
verbose = False
ip_range=[]
ip_ranges=[]
alive_devices=[]
hostname={}

def help():
    
    print('''
    
    Scans the specified network to find and list alive nodes.

    Syntax:  /usr/bin/python netscan.py [-n Network -p Port -f FilePath ] ...
    
    example: /usr/bin/python netscan.py -n 192.168.1.0/24 -p 22 -f /etc/output.json
             /usr/bin/python netscan.py -n 192.168.1.16/30,192.168.2.2/32 -p 22 -f /etc/output.json
    
    args:
    -h --help           Help.
    -v --version        Shows version.        
    -n --network        Network(S) to scan.
    -f --file-path      File path containing file name to save the output.
                        You can write the output in .csv, .txt or .json file formats.

    © 2023 Hamid Sadeghian
    
    ''')
    

def portscan(ips, port):
    for ip in ips:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, int(port)))
        if result == 0:
            alive_devices.append(ip) 
            print(ip, ' port {} is open.'.format(port))
            logging.info('{} port {} is open.'.format(ip, port))
        sock.close()
    return alive_devices

def pingscan(ips):
    ping_str = '-n 2' if  platform.system().lower()=='windows' else '-c 2'
    need_sh = False if  platform.system().lower()=='windows' else True
    for ip in ips:
        args = 'ping ' + ' ' + ping_str + ' ' + ip
        # Ping
        if subprocess.call(args, shell=need_sh) == 0:
            alive_devices.append(ip)   
    return alive_devices

def ips(start, end):
    start = struct.unpack('>I', socket.inet_aton(start))[0]
    end = struct.unpack('>I', socket.inet_aton(end))[0]
    return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)]

def nslook(alive_devices):
    hostname={}
    for i in alive_devices:
        try:
            p=(socket.getnameinfo((i, 0), socket.NI_NAMEREQD))
            hostname[i]= p[0]
        except:
            hostname[i]= 'no dns record'
            pass
    return hostname

def main(argv):
    file = None
    networks=[]
    network=''

    logging.info(' START')
    opts, args = getopt.getopt(argv[1:],'n:f:p:hv',['help','version','network=','file-path=','port='])

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            help()
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
    
    if any((not network, not file, not port)):
        print('Mandatory parameter is missing.')
        help()
        logging.err('Mandatory parameters are missing.')
        sys.exit()

    # find out ip ranges
    for n in networks:
        ip_ranges = IPNetwork(str(n))
        for ip in ip_ranges:
            ip_range.append(str(ip))

    print(networks, 'will be scaned.')
    logging.info('%s will be scaned.' %networks)
    

    #input('Press Enter to Continue...')
    alive_devices = portscan(ip_range, port)
    print(len(ip_range),'IPs scaned.')
    logging.info('%s IPs scaned.'%len(ip_range))

    hosts = nslook(alive_devices)
    
    header = ['IP-Address','Hostname']

    try:
        with open(file, 'w', encoding='UTF8', newline='') as f:
            if '.json' in file:
                json.dump(hosts, f, indent=2)
            elif '.csv' in file:
                writer = csv.DictWriter(f, fieldnames=header)
                writer.writeheader()
                for key in hosts.keys():
                    f.write('%s,%s\n'%(key,hosts[key]))   
            elif '.txt' in file:
                for key in hosts.keys():
                    f.write('%s     %s\n'%(key,hosts[key]))
            else:
                print('Unsupported file extension!')
                logging.error('Unsupported file extension!')
        logging.info('List of hosts inclusive DNS-Name saved in {}'.format(file))

    except IOError:
        print('Error occurred while exporting to file: {0}'.format(file))
        logging.error('Error occurred while exporting to file: {0}'.format(file))

    print('\n',len(hosts),'IP(s) with open port 22 found:',hosts,'\n')
    logging.info('{} IP(s) with open port 22 found: {}'.format(len(hosts), hosts))
    

if __name__ == '__main__':
   main(sys.argv)
