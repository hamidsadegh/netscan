# netscan

    Scans the specified network to find and list alive nodes.

    Syntax:  /usr/bin/python netscan.py [-n Network -p Port -f FilePath ] ...

    example: /usr/bin/python netscan.py -n 192.168.1.0/24 -p 22 -f /etc/output.json
             /usr/bin/python netscan.py -n 192.168.1.16/30,192.168.2.2/32 -p 22 -f /etc/output.json

    args:
    -h --help           Help.
    -v --version        Shows version.
    -n --network        Network(S) to scan.
    -p --port           Port to check.
    -f --file-path      File path containing file name to save the output.
                        You can write the output in .csv, .txt or .json file formats.

    © 2023 Hamid Sadeghian
