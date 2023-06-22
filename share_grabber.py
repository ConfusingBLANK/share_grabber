import os
import argparse
import logging
import sys
import traceback
from impacket.smbconnection import SMBConnection, SessionError

def check_access(conn, share_name):
    read_permission = False
    write_permission = False
    try:
        conn.listPath(share_name, '*')
        read_permission = True
    except SessionError:
        pass

    try:
        filename = '\\tempfile.txt'
        fileContent = b"This is a test"
        conn.putFile(share_name, filename, fileContent)
        conn.getFile(share_name, filename, fileContent)
        conn.deleteFile(share_name, filename)
        write_permission = True
    except SessionError:
        pass

    return read_permission, write_permission

def list_shares(server_name, username, password, domain):
    conn = None
    try:
        conn = SMBConnection(server_name, server_name)
        conn.login(username, password, domain=domain)
        shares = conn.listShares()
        for share in shares:
            share_name = share['shi1_netname'][:-1]
            read, write = check_access(conn, share_name)
            permissions = ''
            if read and write:
                permissions = '[r] [w]'
            elif read:
                permissions = '[r]'
            elif write:
                permissions = '[w]'
            else:
                permissions = 'NO ACCESS'

            print(f"{server_name}\\{share_name} {permissions}")
    except Exception as e:
        handle_error(e, "Failed to list shares")
    finally:
        if conn is not None:
            conn.logoff()

def handle_error(e, message):
    if args.debug:
        logging.error(f"{message}: {e}\n{traceback.format_exc()}")
    else:
        logging.error(f"{message}: {e}")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server-name', required=True, help='IP Address or filename of the server')
    parser.add_argument('-u', '--username', required=True, help='Username')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('-d', '--domain', default='', help='Domain')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    if os.path.isfile(args.server_name):
        with open(args.server_name, 'r') as f:
            hosts = f.read().splitlines()
            for host in hosts:
                print(f"Scanning {host}...")
                list_shares(host, args.username, args.password, args.domain)
    else:
        list_shares(args.server_name, args.username, args.password, args.domain)

if __name__ == '__main__':
    main()
