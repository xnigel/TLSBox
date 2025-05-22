import tkinter as tk
from tkinter import scrolledtext
import threading
import socket
import ssl

class TLSProxy:
    def __init__(self, listen_ip, listen_port, dest_ip, dest_port, logger):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.logger = logger
        self.running = False

    def log(self, message):
        self.logger(f"{message}\n")

    def handle_client(self, client_conn):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
            tls_client = context.wrap_socket(client_conn, server_side=True)

            tls_server_sock = ssl.create_default_context().wrap_socket(
                socket.create_connection((self.dest_ip, self.dest_port)),
                server_hostname=self.dest_ip
            )

            while self.running:
                data = tls_client.recv(4096)
                if not data:
                    break

                self.log(f"[Intercepted] {data.hex()}")
                tls_server_sock.sendall(data)

                response = tls_server_sock.recv(4096)
                self.log(f"[Response] {response.hex()}")
                tls_client.sendall(response)

        except Exception as e:
            self.log(f"[Error] {e}")
        finally:
            client_conn.close()

    def start(self):
        self.running = True
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.listen_ip, self.listen_port))
            sock.listen(5)
            self.log(f"[*] Listening on {self.listen_ip}:{self.listen_port}")
            while self.running:
                conn, _ = sock.accept()
                threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()

    def stop(self):
        self.running = False
        self.log("[*] Proxy stopped.")

#comment for nothing.
class TLSProxyApp:
    def __init__(self, root):
        self.root = root
        self.proxy = None

        root.title("TLS MITM Proxy")

        tk.Label(root, text="Listen IP:").grid(row=0, column=0, sticky="e")
        tk.Label(root, text="Listen Port:").grid(row=1, column=0, sticky="e")
        tk.Label(root, text="Destination IP:").grid(row=2, column=0, sticky="e")
        tk.Label(root, text="Destination Port:").grid(row=3, column=0, sticky="e")

        self.listen_ip = tk.Entry(root)
        self.listen_port = tk.Entry(root)
        self.dest_ip = tk.Entry(root)
        self.dest_port = tk.Entry(root)

        self.listen_ip.insert(0, "0.0.0.0")
        self.listen_port.insert(0, "8443")
        self.dest_ip.insert(0, "example.com")
        self.dest_port.insert(0, "443")

        self.listen_ip.grid(row=0, column=1)
        self.listen_port.grid(row=1, column=1)
        self.dest_ip.grid(row=2, column=1)
        self.dest_port.grid(row=3, column=1)

        self.start_button = tk.Button(root, text="Start Proxy", command=self.start_proxy)
        self.start_button.grid(row=4, column=0, columnspan=2, pady=10)

        self.log_area = scrolledtext.ScrolledText(root, width=80, height=20)
        self.log_area.grid(row=5, column=0, columnspan=2)

    def log(self, message):
        self.log_area.insert(tk.END, message)
        self.log_area.see(tk.END)

    def start_proxy(self):
        if self.proxy:
            self.proxy.stop()

        listen_ip = self.listen_ip.get()
        listen_port = int(self.listen_port.get())
        dest_ip = self.dest_ip.get()
        dest_port = int(self.dest_port.get())

        self.proxy = TLSProxy(listen_ip, listen_port, dest_ip, dest_port, self.log)
        self.proxy.start()
        self.log("[*] Proxy started.\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = TLSProxyApp(root)
    #root.iconbitmap('C:/Python3/NZ.ico')
    root.iconbitmap('NZ.ico')
    root.mainloop()
