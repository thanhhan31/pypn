# -*- coding: utf-8 -*-
"""
 Small Socks5 Proxy Server in Python
 from https://github.com/MisterDaneel/
"""

# Network
import socket
import select
from struct import pack, unpack
# System
import traceback
from threading import Thread, active_count
from signal import signal, SIGINT, SIGTERM
from time import sleep
import sys
import logging
import argparse

#
# Constants
#
VER = b'\x05'  # PROTOCOL VERSION 5
M_NOAUTH = b'\x00'  # NO AUTHENTICATION REQUIRED
M_NOTAVAILABLE = b'\xff'  # NO ACCEPTABLE METHODS
CMD_CONNECT = b'\x01'  # CONNECT
ATYP_IPV4 = b'\x01'  # IP V4 address
ATYP_DOMAINNAME = b'\x03'  # DOMAINNAME

# Thiết lập logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class ExitStatus:
    """ Manage exit status """
    def __init__(self):
        self.exit = False

    def set_status(self, status):
        self.exit = status

    def get_status(self):
        return self.exit

def error(msg="", err=None):
    """ Log exception stack trace """
    if msg and err:
        logging.error(f"{msg} - Code: {err[0]}, Message: {err[1]}")
    else:
        logging.error(traceback.format_exc())

def proxy_loop(socket_src, socket_dst):
    """ Wait for network activity """
    while not EXIT.get_status():
        try:
            reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
        except select.error as err:
            error("Select failed", err)
            return
        if not reader:
            continue
        try:
            for sock in reader:
                data = sock.recv(BUFSIZE)
                if not data:
                    return
                if sock is socket_dst:
                    socket_src.send(data)
                else:
                    socket_dst.send(data)
        except socket.error as err:
            error("Loop failed", err)
            return

def connect_to_dst(dst_addr, dst_port):
    """ Connect to desired destination """
    sock = create_socket()
    if OUTGOING_INTERFACE:
        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                OUTGOING_INTERFACE.encode(),
            )
        except PermissionError as err:
            logging.error("Only root can set OUTGOING_INTERFACE parameter")
            EXIT.set_status(True)
            return None
    try:
        sock.connect((dst_addr, dst_port))
        return sock
    except socket.error as err:
        error("Failed to connect to DST", err)
        return None

def request_client(wrapper):
    """ Client request details """
    try:
        s5_request = wrapper.recv(BUFSIZE)
        if len(s5_request) < 10:  # Kiểm tra độ dài tối thiểu
            return False
    except socket.error as err:
        error("Failed to receive request", err)
        return False

    # Check VER, CMD and RSV
    if (
            s5_request[0:1] != VER or
            s5_request[1:2] != CMD_CONNECT or
            s5_request[2:3] != b'\x00'
    ):
        return False

    # IPV4
    if s5_request[3:4] == ATYP_IPV4:
        if len(s5_request) != 10:
            return False
        dst_addr = socket.inet_ntoa(s5_request[4:8])
        dst_port = unpack('>H', s5_request[8:10])[0]
    # DOMAIN NAME
    elif s5_request[3:4] == ATYP_DOMAINNAME:
        domain_length = s5_request[4]
        if len(s5_request) != 5 + domain_length + 2:
            return False
        dst_addr = s5_request[5:5 + domain_length].decode()
        dst_port = unpack('>H', s5_request[5 + domain_length:])[0]
    else:
        return False
    logging.info(f"Request to {dst_addr}:{dst_port}")
    return (dst_addr, dst_port)

def request(wrapper):
    """ Handle SOCKS5 request """
    dst = request_client(wrapper)
    rep = b'\x07'  # Request rejected or failed
    bnd = b'\x00' * 6  # BND.ADDR và BND.PORT

    socket_dst = None
    if dst:
        socket_dst = connect_to_dst(dst[0], dst[1])
        if socket_dst:
            rep = b'\x00'  # Succeeded
            bnd = socket.inet_aton(socket_dst.getsockname()[0])
            bnd += pack(">H", socket_dst.getsockname()[1])
        else:
            rep = b'\x01'  # General SOCKS server failure

    reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
    try:
        wrapper.sendall(reply)
    except socket.error as err:
        error("Failed to send reply", err)

    # Start proxy if successful
    if rep == b'\x00' and socket_dst:
        proxy_loop(wrapper, socket_dst)

    # Clean up
    wrapper.close()
    if socket_dst:
        socket_dst.close()

def subnegotiation_client(wrapper):
    """ Client subnegotiation """
    try:
        identification_packet = wrapper.recv(BUFSIZE)
        if len(identification_packet) < 2:
            return M_NOTAVAILABLE
    except socket.error as err:
        error("Failed to receive identification packet", err)
        return M_NOTAVAILABLE

    if identification_packet[0:1] != VER:
        return M_NOTAVAILABLE

    nmethods = identification_packet[1]
    if len(identification_packet) != 2 + nmethods:
        return M_NOTAVAILABLE

    methods = identification_packet[2:2 + nmethods]
    if ord(M_NOAUTH) in methods:
        return M_NOAUTH
    return M_NOTAVAILABLE

def subnegotiation(wrapper):
    """ Server subnegotiation """
    method = subnegotiation_client(wrapper)
    if method != M_NOAUTH:
        return False
    reply = VER + method
    try:
        wrapper.sendall(reply)
    except socket.error as err:
        error("Failed to send method selection", err)
        return False
    return True

def connection(wrapper):
    """ Handle client connection """
    if subnegotiation(wrapper):
        request(wrapper)
    else:
        wrapper.close()

def create_socket():
    """ Create an INET, STREAMing socket """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("Failed to create socket", err)
        sys.exit(1)
    return sock

def bind_port(sock, addr, port):
    """ Bind and listen on socket """
    try:
        logging.info(f'Bind {addr}:{port}')
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((addr, port))
        sock.listen(10)
    except socket.error as err:
        error("Bind or listen failed", err)
        sock.close()
        sys.exit(1)
    return sock

def exit_handler(signum, frame):
    """ Signal handler """
    logging.info(f'Signal handler called with signal {signum}')
    EXIT.set_status(True)

def parse_args():
    """ Parse command-line arguments """
    parser = argparse.ArgumentParser(description="SOCKS5 Proxy Server")
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=9050, help='Bind port (default: 9050)')
    parser.add_argument('--interface', type=str, default='', help='Outgoing interface (e.g., eth0)')
    parser.add_argument('--max-threads', type=int, default=200, help='Max threads (default: 200)')
    parser.add_argument('--bufsize', type=int, default=2048, help='Buffer size (default: 2048)')
    parser.add_argument('--timeout', type=int, default=5, help='Socket timeout in seconds (default: 5)')
    return parser.parse_args()

def main():
    """ Main function """
    args = parse_args()

    global LOCAL_ADDR, LOCAL_PORT, OUTGOING_INTERFACE, MAX_THREADS, BUFSIZE, TIMEOUT_SOCKET
    LOCAL_ADDR = args.host
    LOCAL_PORT = args.port
    OUTGOING_INTERFACE = args.interface
    MAX_THREADS = args.max_threads
    BUFSIZE = args.bufsize
    TIMEOUT_SOCKET = args.timeout

    new_socket = create_socket()
    bind_port(new_socket, LOCAL_ADDR, LOCAL_PORT)

    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)

    while not EXIT.get_status():
        if active_count() > MAX_THREADS:
            sleep(3)
            continue
        try:
            wrapper, _ = new_socket.accept()
            wrapper.setblocking(1)
        except socket.timeout:
            continue
        except socket.error as err:
            error("Accept failed", err)
            continue

        recv_thread = Thread(target=connection, args=(wrapper,))
        recv_thread.start()

    new_socket.close()

EXIT = ExitStatus()
if __name__ == '__main__':
    main()