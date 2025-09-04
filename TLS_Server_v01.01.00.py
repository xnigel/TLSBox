#   Initial version was built in May 2025                                        #
#                                                                                #
#   Version Number Defination:                                                   #
#   v00.01.01 20250501                                                           #
#    -- -- --                                                                    #
#     |  |  |                                                                    #
#     |  |  +------     GUI Updates                                              #
#     |  +---------     Crypto Function Updates                                  #
#     +------------     Published Version (Major Change)                         #
#                                                                                #
# _______________________________________________________________________________#
#                                                                                
#   Project created in May 2025
#   01. v00.01.01 was created with basic GUI and TLS proxy functionality.
#   02. v00.02.01 was updated with logging, packet modification, and export features.
#   03. v00.03.01 Fixed the ico issue.
#   04. v01.00.00 Final release version.
#   05. v01.00.01 Fixing auto disconnection. 2025.07.30
#   06. v01.00.02 Fixing auto disconnection and adding TLSv1.3 support. 2025.07.31
#   07. v01.01.00 Changed icon and logo
# _______________________________________________________________________________

import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext
import socket
import threading
import os
from OpenSSL import SSL, crypto
import time
import base64
import tempfile

# === Paste your Base64 encoded PNG string here ===
ICON_PNG_BASE64 = """
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cGUvUmVzb3VyY2VFdmVudCMiCiAgICB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iCiAgICB4bWxuczpleGlmPSJodHRwOi8vbnMuYWRvYmUuY29tL2V4aWYvMS4wLyIKICAgIHhtbG5zOkdJTVA9Imh0dHA6Ly93d3cuZ2ltcC5vcmcveG1wLyIKICAgIHhtbG5zOmlwdGNFeHQ9Imh0dHA6Ly9pcHRjLm9yZy9zdGQvSXB0YzR4bXBFeHQvMjAwOC0wMi0yOS8iCiAgICB4bWxuczpwaG90b3Nob3A9Imh0dHA6Ly9ucy5hZG9iZS5jb20vcGhvdG9zaG9wLzEuMC8iCiAgICB4bWxuczp0aWZmPSJodHRwOi8vbnMuYWRvYmUuY29tL3RpZmYvMS4wLyIKICAgIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIKICAgeG1wTU06RG9jdW1lbnRJRD0iZ2ltcDpkb2NpZDpnaW1wOmE4MzRhNmI1LWQyMDAtNGEzZC05NWZmLTI2ODlkNzIzOTlkMCIKICAgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDphNDczZjIyNy02MTAwLTQ3NTAtOGI4OC00NDUyMzkyOWQxOWMiCiAgIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDoxZTkwM2UyNy1jZmMwLTQ4NzAtYjE0Mi1mZTI4MjczMTQ3YTAiCiAgIGRjOkZvcm1hdD0iaW1hZ2UvcG5nIgogICBleGlmOkRhdGVUaW1lT3JpZ2luYWw9IjIwMjUtMDktMDNUMDY6Mzk6MTArMDA6MDAiCiAgIEdJTVA6QVBJPSIyLjAiCiAgIEdJTVA6UGxhdGZvcm09IldpbmRvd3MiCiAgIEdJTVA6VGltZVN0YW1wPSIxNzU2ODgxODY3NzE2MTExIgogICBHSU1QOlZlcnNpb249IjIuMTAuMzAiCiAgIGlwdGNFeHQ6RGlnaXRhbFNvdXJjZUZpbGVUeXBlPSJodHRwOi8vY3YuaXB0Yy5vcmcvbmV3c2NvZGVzL2RpZ2l0YWxzb3VyY2V0eXBlL2NvbXBvc2l0ZVdpdGhUcmFpbmVkQWxnb3JpdGhtaWNNZWRpYSIKICAgaXB0Y0V4dDpEaWdpdGFsU291cmNlVHlwZT0iaHR0cDovL2N2LmlwdGMub3JnL25ld3Njb2Rlcy9kaWdpdGFsc291cmNldHlwZS9jb21wb3NpdGVXaXRoVHJhaW5lZEFsZ29yaXRobWljTWVkaWEiCiAgIHBob3Rvc2hvcDpDcmVkaXQ9IkVkaXRlZCB3aXRoIEdvb2dsZSBBSSIKICAgcGhvdG9zaG9wOkRhdGVDcmVhdGVkPSIyMDI1LTA5LTAzVDA2OjM5OjEwKzAwOjAwIgogICB0aWZmOk9yaWVudGF0aW9uPSIxIgogICB4bXA6Q3JlYXRvclRvb2w9IkdJTVAgMi4xMCI+CiAgIDx4bXBNTTpIaXN0b3J5PgogICAgPHJkZjpTZXE+CiAgICAgPHJkZjpsaQogICAgICBzdEV2dDphY3Rpb249InNhdmVkIgogICAgICBzdEV2dDpjaGFuZ2VkPSIvIgogICAgICBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjllMmQxYTUwLTcyMWEtNDU1MC05Y2RkLTA2ZmM0ZDJiYTQ3OCIKICAgICAgc3RFdnQ6c29mdHdhcmVBZ2VudD0iR2ltcCAyLjEwIChXaW5kb3dzKSIKICAgICAgc3RFdnQ6d2hlbj0iMjAyNS0wOS0wM1QxNjo0MjoyNCIvPgogICAgIDxyZGY6bGkKICAgICAgc3RFdnQ6YWN0aW9uPSJzYXZlZCIKICAgICAgc3RFdnQ6Y2hhbmdlZD0iLyIKICAgICAgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDpkZmMxZjVmOC00NTIxLTQ5YzMtODA0YS03ODMzYzY4NThhMTkiCiAgICAgIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkdpbXAgMi4xMCAoV2luZG93cykiCiAgICAgIHN0RXZ0OndoZW49IjIwMjUtMDktMDNUMTY6NDQ6MjciLz4KICAgIDwvcmRmOlNlcT4KICAgPC94bXBNTTpIaXN0b3J5PgogIDwvcmRmOkRlc2NyaXB0aW9uPgogPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg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
"""

class TLSServerApp:
    def __init__(self, master):
        self.master = master
        Server_ver = "01.01.00"
        Server_yr = "2025.08.04"
        master.title("TLS Server" + " (v" + Server_ver +")" + " - " + Server_yr + " - Nigel Zhai")
        master.geometry("500x700")
        master.minsize(500, 700)
        master.maxsize(500, 700)
        master.resizable(True, True)

        self.set_window_icon()

        self.server_running = False
        self.server_socket = None
        self.server_thread = None
        self.connected_clients = []

        config_frame = ttk.LabelFrame(master, text="Server Configuration", padding="5")
        config_frame.pack(padx=10, pady=10, fill="x", expand=False)

        self.cert_file_var = tk.StringVar()
        self.key_file_var = tk.StringVar()
        self.ca_file_var = tk.StringVar()
        self.port_var = tk.StringVar(value="443")
        self.tls_version_var = tk.StringVar(value="TLSv1.2")

        row = 0
        ttk.Label(config_frame, text="Server Certificate:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(config_frame, textvariable=self.cert_file_var, width=50).grid(row=row, column=1, padx=5, pady=2, sticky="ew")
        ttk.Button(config_frame, text="Browse", command=lambda: self.browse_file(self.cert_file_var, "*.pem")).grid(row=row, column=2, pady=2)

        row += 1
        ttk.Label(config_frame, text="Server Private Key:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(config_frame, textvariable=self.key_file_var, width=50).grid(row=row, column=1, padx=5, pady=2, sticky="ew")
        ttk.Button(config_frame, text="Browse", command=lambda: self.browse_file(self.key_file_var, "*.key")).grid(row=row, column=2, pady=2)

        row += 1
        ttk.Label(config_frame, text="CA Certificate:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(config_frame, textvariable=self.ca_file_var, width=50).grid(row=row, column=1, padx=5, pady=2, sticky="ew")
        ttk.Button(config_frame, text="Browse", command=lambda: self.browse_file(self.ca_file_var, "*.pem")).grid(row=row, column=2, pady=2)

        row += 1
        ttk.Label(config_frame, text="Port:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(config_frame, textvariable=self.port_var, width=10).grid(row=row, column=1, padx=5, pady=2, sticky="w")

        row += 1
        ttk.Label(config_frame, text="TLS Version:").grid(row=row, column=0, sticky="w", pady=2)
        tls_versions = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
        self.tls_version_combobox = ttk.Combobox(config_frame, textvariable=self.tls_version_var, values=tls_versions, state="readonly", width=15)
        self.tls_version_combobox.grid(row=row, column=1, padx=5, pady=2, sticky="w")
        self.tls_version_combobox.set("TLSv1.2")
        config_frame.columnconfigure(1, weight=1)

        button_frame = ttk.Frame(master, padding="5")
        button_frame.pack(padx=10, pady=5, fill="x", expand=False)

        self.stop_button = ttk.Button(button_frame, text="Stop Server", command=self.stop_server, state="disabled", style="Red.TButton")
        self.stop_button.pack(side="right", padx=5)
        
        self.start_button = ttk.Button(button_frame, text="Start Server", command=self.start_server, style="Green.TButton")
        self.start_button.pack(side="right", padx=5)

        message_frame = ttk.LabelFrame(master, text="Send Message to Clients", padding="5")
        message_frame.pack(padx=10, pady=5, fill="x", expand=False)

        self.message_entry = ttk.Entry(message_frame, width=50)
        self.message_entry.pack(side="left", padx=5, fill="x", expand=True)
        self.message_entry.bind("<Return>", self.send_message_event)
        self.send_button = ttk.Button(message_frame, text="Send", command=self.send_message, state="disabled")
        self.send_button.pack(side="left", padx=5)

        log_frame = ttk.LabelFrame(master, text="Server Log", padding="5")
        log_frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state="disabled", width=80, height=20)
        self.log_text.pack(fill="both", expand=True)

        style = ttk.Style()
        style.configure("TLabel", font=("Inter", 9))
        style.configure("TButton", font=("Inter", 9, "bold"))
        style.configure("TEntry", font=("Inter", 9))
        style.configure("TCombobox", font=("Inter", 9))
        style.configure("TLabelFrame", font=("Inter", 9, "bold"))
        self.log_text.tag_configure("info", foreground="blue")
        self.log_text.tag_configure("success", foreground="green")
        self.log_text.tag_configure("error", foreground="red")
        self.log_text.tag_configure("warning", foreground="orange")

        # Custom button styles
        style.configure("Green.TButton", background="#D1FFBD", foreground="black")
        style.map("Green.TButton",
                  background=[("active", "darkgreen"), ("disabled", "lightgray")],
                  foreground=[("active", "white"), ("disabled", "darkgray")])

        style.configure("Red.TButton", background="#FF5C5C", foreground="black")
        style.map("Red.TButton",
                  background=[("active", "darkred"), ("disabled", "lightgray")],
                  foreground=[("active", "white"), ("disabled", "darkgray")])


    def set_window_icon(self):
        try:
            icon_data = base64.b64decode(ICON_PNG_BASE64)
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
                f.write(icon_data)
                icon_path = f.name
            photo = tk.PhotoImage(file=icon_path)
            self.master.iconphoto(True, photo)
            os.remove(icon_path)
        except Exception as e:
            self.log_message(f"Error setting icon: \n{e}", "error")

    def browse_file(self, var, file_type):
        file_path = filedialog.askopenfilename(filetypes=[("Certificate Files", file_type), ("All Files", "*.*")])
        if file_path:
            var.set(file_path)

    def log_message(self, message, tag=None):
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def _update_button_states(self):
        if self.server_running:
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
            self.send_button.config(state="normal")
            self.tls_version_combobox.config(state="disabled")
        else:
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.send_button.config(state="disabled")
            self.tls_version_combobox.config(state="readonly")

    def start_server(self):
        cert_file = self.cert_file_var.get()
        key_file = self.key_file_var.get()
        ca_file = self.ca_file_var.get()
        port = self.port_var.get()
        tls_version = self.tls_version_var.get()

        if not all([cert_file, key_file, port]):
            self.log_message("Please provide Server Certificate, Server Private Key, and Port.", "warning")
            return

        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            self.log_message("Certificate or Key file not found.", "error")
            return

        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError("Port must be between 1 and 65535.")
        except ValueError as e:
            self.log_message(f"Invalid Port: \n{e}", "error")
            return

        self.log_message(f"Starting server on port {port} with TLS {tls_version}...", "info")
        self.server_running = True
        self._update_button_states()

        self.server_thread = threading.Thread(target=self.run_server, args=(cert_file, key_file, ca_file, port, tls_version))
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop_server(self):
        if self.server_running:
            self.log_message("Stopping server...", "info")
            self.server_running = False
            if self.server_socket:
                try:
                    self.server_socket.shutdown(socket.SHUT_RDWR)
                    self.server_socket.close()
                except OSError as e:
                    self.log_message(f"Error shutting down server socket: \n{e}", "error")
                self.server_socket = None

            # Close all active client connections
            for client_info in list(self.connected_clients):
                ssl_client_socket, client_address = client_info
                try:
                    ssl_client_socket.shutdown()
                    ssl_client_socket.close()
                    self.log_message(f"Client {client_address[0]}:{client_address[1]} disconnected.", "info")
                except Exception as e:
                    self.log_message(f"Error closing client {client_address[0]}:{client_address[1]} connection: \n{e}", "error")
                self.connected_clients.remove(client_info)
            self.connected_clients.clear()

            self.log_message("Server stopped.", "success")
            self._update_button_states()
        else:
            self.log_message("Server is not running.", "warning")

    def run_server(self, cert_file, key_file, ca_file, port, tls_version):
        try:
            ctx = SSL.Context(self._get_tls_method(tls_version))
            ctx.use_certificate_file(cert_file)
            ctx.use_privatekey_file(key_file)

            if ca_file and os.path.exists(ca_file):
                ctx.load_verify_locations(ca_file)
                ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verify_cb)
            else:
                ctx.set_verify(SSL.VERIFY_NONE, self.verify_cb)
                self.log_message("No CA Certificate provided or found. Client authentication will not be performed.", "warning")

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('', port))
            self.server_socket.listen(5)
            self.log_message(f"Listening for connections on port {port}...", "info")

            while self.server_running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.log_message(f"Accepted connection from {client_address[0]}:{client_address[1]}", "info")
                    ssl_client_socket = SSL.Connection(ctx, client_socket)
                    ssl_client_socket.set_accept_state()
                    self.connected_clients.append((ssl_client_socket, client_address))
                    threading.Thread(target=self.handle_client, args=(ssl_client_socket, client_address)).start()
                except SSL.Error as e:
                    self.log_message(f"SSL handshake error: \n{e}", "error")
                except socket.timeout:
                    continue # Continue accepting if timeout (non-blocking server)
                except OSError as e:
                    if self.server_running: # Only log if server was intended to be running
                        self.log_message(f"Socket accept error: \n{e}", "error")
                    break # Break if server socket is closed or unrecoverable error
                except Exception as e:
                    self.log_message(f"Unexpected error in accept loop: \n{e}", "error")
                    if not self.server_running:
                        break # Exit loop if server stopped

        except Exception as e:
            self.log_message(f"Server setup error: \n{e}", "error")
        finally:
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            if self.server_running: # If an error occurred that stopped the server
                self.server_running = False
                self._update_button_states() # Reset buttons if server stopped unexpectedly

    def _get_tls_method(self, version_str):
        if version_str == "TLSv1.0":
            return SSL.TLSv1_METHOD
        elif version_str == "TLSv1.1":
            return SSL.TLSv1_1_METHOD
        elif version_str == "TLSv1.2":
            return SSL.TLSv1_2_METHOD
        elif version_str == "TLSv1.3":
            # For TLSv1.3, you typically use TLS_METHOD which allows all TLS versions
            # and then configure minimum/maximum protocol versions.
            # OpenSSL.SSL.TLS_METHOD is available from PyOpenSSL 0.15 onwards.
            # For strict TLSv1.3, you might need to combine it with context options.
            # For simplicity, if TLSv1.3 is chosen, we'll use TLS_METHOD and assume
            # the underlying OpenSSL will negotiate the highest supported version.
            # To strictly enforce TLSv1.3, additional context configuration might be needed.
            # For this example, TLS_METHOD is generally sufficient.
            return SSL.TLS_METHOD
        else:
            self.log_message(f"Unsupported TLS version: {version_str}. Defaulting to TLSv1.2.", "warning")
            return SSL.TLSv1_2_METHOD

    def verify_cb(self, conn, cert, errnum, depth, preverify_ok):
        if not preverify_ok:
            self.log_message(f"Certificate verification failed: {errnum} at depth {depth}", "warning")
        else:
            self.log_message("Certificate verified successfully.", "success")
        return preverify_ok

    def handle_client(self, ssl_client_socket, client_address):
        client_ip, client_port = client_address
        try:
            ssl_client_socket.do_handshake()
            self.log_message(f"TLS Handshake successful with {client_ip}:{client_port}", "success")
            peer_cert = ssl_client_socket.get_peer_certificate()
            if peer_cert:
                self.log_message(f"Client certificate subject: {peer_cert.get_subject()}", "info")
            else:
                self.log_message("Client did not present a certificate.", "info")

            while self.server_running:
                try:
                    data = ssl_client_socket.recv(4096)
                    if not data:
                        break
                    decoded_data = data.decode('utf-8', errors='ignore').strip()
                    self.log_message(f"Received from {client_ip}:{client_port}: {decoded_data}", "info")
                    response = f"Echo: {decoded_data}"
                    ssl_client_socket.sendall(response.encode('utf-8'))
                    self.log_message(f"Sent to {client_ip}:{client_port}: {response}", "info")

                except SSL.WantReadError:
                    # No data to read, try again later. Non-blocking socket.
                    time.sleep(0.1)
                    continue
                except SSL.Error as e:
                    self.log_message(f"SSL data error with {client_ip}:{client_port}: \n{e}", "error")
                    break
                except socket.error as e:
                    self.log_message(f"Socket error with {client_ip}:{client_port}: \n{e}", "error")
                    break
                except Exception as e:
                    self.log_message(f"Error handling client {client_ip}:{client_port}: \n{e}", "error")
                    break
        except SSL.Error as e:
            self.log_message(f"TLS Handshake failed with {client_ip}:{client_port}: \n{e}", "error")
        except Exception as e:
            self.log_message(f"Unexpected error during client handling for {client_ip}:{client_port}: \n{e}", "error")
        finally:
            # Ensure the client is removed from the active connections list
            client_removed = False
            for i, (conn, addr) in enumerate(self.connected_clients):
                if conn == ssl_client_socket:
                    del self.connected_clients[i]
                    client_removed = True
                    break

            if client_removed:
                self.log_message(f"Client {client_ip}:{client_port} removed from active connections. Total: {len(self.connected_clients)}", "info")
            
            try:
                ssl_client_socket.shutdown()
                ssl_client_socket.close()
            except SSL.Error as e:
                self.log_message(f"Error closing SSL connection for {client_ip}:{client_port}: \n{e}", "error")
            except OSError as e:
                self.log_message(f"OS error closing connection for {client_ip}:{client_port}: \n{e}", "error")
            except Exception as e:
                self.log_message(f"Error closing connection for {client_ip}:{client_port}: \n{e}", "error")

            # Reset buttons if this was the last client and the server is considered running
            if len(self.connected_clients) == 0 and self.server_running:
                self.log_message("All clients disconnected. Resetting server buttons to allow new connection.", "info")
                # Instead of directly stopping, which might terminate the server,
                # just update the UI state to reflect that a new connection is possible.
                # However, the user's request for "reset these two buttons for a new TLS connection"
                # implies restarting the server or preparing for a new server instance.
                # If the server thread is still running and listening, "Start Server" should remain disabled.
                # The most consistent behavior for resetting buttons is to stop the server entirely if the last
                # client disconnects due to an error.

                # If the intent is to allow a fresh start, then stopping the server is the right action.
                # This will disable 'Stop Server' and enable 'Start Server'.
                self.stop_server()


    def send_message_event(self, event):
        self.send_message()

    def send_message(self):
        message = self.message_entry.get()
        if not message:
            self.log_message("Message cannot be empty.", "warning")
            return

        if not self.connected_clients:
            self.log_message("No clients connected to send message.", "warning")
            return

        for ssl_client_socket, client_address in list(self.connected_clients):
            try:
                ssl_client_socket.sendall(message.encode('utf-8'))
                self.log_message(f"Sent to {client_address[0]}:{client_address[1]}: {message}", "info")
            except SSL.Error as e:
                self.log_message(f"SSL send error to {client_address[0]}:{client_address[1]}: \n{e}", "error")
                # Remove disconnected client
                if (ssl_client_socket, client_address) in self.connected_clients:
                    self.connected_clients.remove((ssl_client_socket, client_address))
                    self.log_message(f"Client {client_address[0]}:{client_address[1]} removed due to send error. Total: {len(self.connected_clients)}", "info")
                    if len(self.connected_clients) == 0:
                        self.stop_server() # Reset buttons if last client disconnected due to send error
            except socket.error as e:
                self.log_message(f"Socket send error to {client_address[0]}:{client_address[1]}: \n{e}", "error")
                # Remove disconnected client
                if (ssl_client_socket, client_address) in self.connected_clients:
                    self.connected_clients.remove((ssl_client_socket, client_address))
                    self.log_message(f"Client {client_address[0]}:{client_address[1]} removed due to socket error. Total: {len(self.connected_clients)}", "info")
                    if len(self.connected_clients) == 0:
                        self.stop_server() # Reset buttons if last client disconnected due to send error
            except Exception as e:
                self.log_message(f"Error sending message to {client_address[0]}:{client_address[1]}: \n{e}", "error")
        self.message_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = TLSServerApp(root)
    root.mainloop()