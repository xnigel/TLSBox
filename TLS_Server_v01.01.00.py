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
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
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