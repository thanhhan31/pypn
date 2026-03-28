import subprocess
import re
import threading
import time
import signal
import os
import logging

class VPNConnection:
    def __init__(self, config_path, proxy_port, max_reconnect_attempts=3):
        self.config_path = config_path
        self.proxy_port = proxy_port
        self.max_reconnect_attempts = max_reconnect_attempts

        self.config_name = os.path.basename(config_path)
        self.is_connected = False
        self.tun_number = -1
        self.socks5_server = None

        self.self_exit = False
        self.on_exit = False
        
        self.tun_number_regex = re.compile(r'tun(\d+)')

        self.connector_thread = None
        self.resolved_ip : str = None

    def handle_output(self, line):
        if not line:
            return

        # logging.debug(f"{self.config_name} - openvpn - {line}")

        if "TUN/TAP device" in line and "opened" in line:
            match = self.tun_number_regex.search(line)
            if match:
                self.tun_number = int(match.group(1))
            else:
                self.tun_number = -1
                logging.error(f"{self.config_name}: Cannot parse tun device number: {line}")

        elif "Exiting due to fatal error" in line or "process exiting" in line:
            # 2025-05-07 16:03:04,116 - DEBUG - 122.208.194.129_JP.ovpn - 2025-05-07 16:03:04 AUTH: Received control message: AUTH_FAILED
            # 2025-05-07 16:03:04,116 - DEBUG - 122.208.194.129_JP.ovpn - 2025-05-07 16:03:04 SIGTERM[soft,auth-failure] received, process exiting
            if self.is_connected:
                self.is_connected = False
            self.self_exit = True

        elif "Initialization Sequence Completed" in line:
            if not self.is_connected:
                self.is_connected = True

            logging.info(f"{self.config_name}: Connected")
            
            if self.socks5_server is None:
                self.start_proxy_server()

        elif "SIGUSR1" in line and "received, process restarting" in line:
            if self.is_connected:
                self.is_connected = False

            logging.warning(f"{self.config_name}: Reconnecting")

    def create_and_connect_vpn(self):
        try:
            proc = subprocess.Popen(
                [
                    "openvpn",
                    "--config", self.config_path,
                    "--auth-user-pass", os.path.join(os.getcwd(), "up.txt"),
                    "--connect-retry", "1", "1",
                    "--connect-retry-max", str(self.max_reconnect_attempts),
                    "--resolv-retry", "1",
                    "--connect-timeout", "10",
                    "--keepalive", "10", "60"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            def read_output():
                for line in proc.stdout:
                    self.handle_output(line.strip())

            output_thread = threading.Thread(target=read_output)
            output_thread.daemon = True
            output_thread.start()

            while not proc.poll():
                time.sleep(2)
                if self.on_exit or self.self_exit:
                    logging.debug(f"{self.config_name} - Sending SIGTERM to OpenVPN process")
                    proc.send_signal(signal.SIGTERM)
                    break
            
            self.is_connected = False
            logging.debug(f"{self.config_name} - Waiting for OpenVPN process to finish")
            proc.wait()
            logging.debug(f"{self.config_name} - OpenVPN process finished")
            if self.socks5_server:
                self.socks5_server.send_signal(signal.SIGTERM)
                self.socks5_server.wait()

                if self.socks5_server.stdout:
                    self.socks5_server.stdout.close()

            logging.debug(f"{self.config_name} - Exited")
        except Exception as e:
            logging.error(f"{self.config_name} - Connecting thread error: {str(e)}")
        finally:
            if proc and proc.poll() is None:
                logging.debug(f"{self.config_name} - Sending SIGTERM to OpenVPN process in finally block")
                proc.send_signal(signal.SIGTERM)
                proc.wait()

            if proc.stdout:
                proc.stdout.close()

            if self.socks5_server is not None:
                if self.socks5_server.poll() is None:
                    logging.debug(f"{self.config_name} - Sending SIGTERM to socks5 server in finally block")
                    self.socks5_server.send_signal(signal.SIGTERM)
                    self.socks5_server.wait()

                if self.socks5_server.stdout:
                    self.socks5_server.stdout.close()

            if not self.on_exit or not self.self_exit:
                logging.debug(f"{self.config_name} - Exiting with finally block")
                self.self_exit = True

    def start_connect(self):
        self.connector_thread = threading.Thread(target=self.create_and_connect_vpn)
        self.connector_thread.start()

    def stop_connect(self):
        logging.debug(f"{self.config_name} - Stopping connection")
        self.on_exit = True
        self.is_connected = False
        if self.connector_thread:
            logging.debug(f"{self.config_name} - Waiting for connection thread to finish")
            self.connector_thread.join()

    def start_proxy_server(self):
        try:
            self.socks5_server = subprocess.Popen(
                [
                    "python3",
                    "socks5_proxy.py",
                    "--host", "0.0.0.0",
                    "--port", str(self.proxy_port),
                    "--max-threads", "100",
                    "--bufsize", "4096",
                    "--timeout", "30",
                    "--interface", f"tun{self.tun_number}"
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                # text=True
            )
            logging.info(f"{self.config_name} - Proxy server listening at port {self.proxy_port}")
            
            # def read_output():
            #     for line in self.socks5_server.stderr:
            #         logging.debug(f"{self.config_name} - socks5_proxy - {line.strip()}")

            # output_thread = threading.Thread(target=read_output)
            # output_thread.daemon = True
            # output_thread.start()

        except Exception as e:
            logging.debug(f"{self.config_name} - Failed to start socks5 server: {e}")

    def change_proxy_port(self, new_port):
        if self.socks5_server:
            self.socks5_server.send_signal(signal.SIGTERM)
            self.socks5_server.wait()

            if self.socks5_server.stdout:
                self.socks5_server.stdout.close()

        self.proxy_port = new_port
        self.start_proxy_server()