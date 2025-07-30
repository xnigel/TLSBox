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
#
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
        Server_ver = "01.00.01"
        Server_yr = "2025.07.30"
        master.title("TLS Server" + " (v" + Server_ver +")" + " - " + Server_yr + " - nigel.zhai@ul.com")
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
        self.log_text.tag_configure("sent", foreground="darkgreen")
        self.log_text.tag_configure("received", foreground="purple")

        style.configure("Green.TButton", background="#D1FFBD", foreground="black")
        style.map("Green.TButton",
                  background=[("active", "darkgreen"), ("disabled", "lightgray")],
                  foreground=[("active", "white"), ("disabled", "darkgray")])

        style.configure("Red.TButton", background="#FF5C5C", foreground="black")
        style.map("Red.TButton",
                  background=[("active", "darkred"), ("disabled", "lightgray")],
                  foreground=[("active", "white"), ("disabled", "darkgray")])

        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def set_window_icon(self):
        try:
            icon_data = base64.b64decode(ICON_PNG_BASE64)
            try:
                photo_image = tk.PhotoImage(data=icon_data)
                self.master.iconphoto(True, photo_image)
            except tk.TclError:
                print("PhotoImage failed, attempting .ico fallback...")
                temp_ico_path = os.path.join(tempfile.gettempdir(), "temp_icon.ico")
                with open(temp_ico_path, "wb") as f:
                    f.write(icon_data)
                self.master.iconbitmap(temp_ico_path)
                os.remove(temp_ico_path)
        except Exception as e:
            print(f"Error setting PNG icon from Base64 or ICO fallback: {e}")
            print("Ensure the Base64 string is correct and represents a valid PNG or ICO image.")
            self.master.iconbitmap(default="::tk::icons::question")

    def browse_file(self, var, file_types):
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", file_types), ("All files", "*.*")])
        if file_path:
            var.set(file_path)

    def log_message(self, message, tag="info"):
        self.master.after(0, lambda: self._insert_log_message(message, tag))

    def _insert_log_message(self, message, tag):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def update_server_control_buttons(self):
        """Updates the state of Start/Stop/Send buttons based on server running status and connected clients."""
        self.master.after(0, self._update_server_control_buttons_thread_safe)

    def _update_server_control_buttons_thread_safe(self):
        if self.server_running:
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
            self.send_button.config(state="normal" if self.connected_clients else "disabled")
        else:
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.send_button.config(state="disabled")

    def start_server(self):
        if self.server_running:
            self.log_message("Server is already running.", "warning")
            return

        cert_file = self.cert_file_var.get()
        key_file = self.key_file_var.get()
        ca_file = self.ca_file_var.get()
        port_str = self.port_var.get()
        tls_version = self.tls_version_var.get()

        if not all([cert_file, key_file]):
            self.log_message("Error: Server Certificate and Private Key are required.", "error")
            return
        if not os.path.exists(cert_file):
            self.log_message(f"Error: Certificate file not found: {cert_file}", "error")
            return
        if not os.path.exists(key_file):
            self.log_message(f"Error: Private key file not found: {key_file}", "error")
            return
        if ca_file and not os.path.exists(ca_file):
            self.log_message(f"Error: CA Certificate file not found: {ca_file}", "error")
            return

        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            self.log_message("Error: Invalid port number. Please enter a number between 1 and 65535.", "error")
            return

        self.server_running = True
        self.update_server_control_buttons() # Update buttons immediately after setting server_running
        self.log_message(f"Attempting to start server on port {port} with minimum TLS version {tls_version}...", "info")

        self.server_thread = threading.Thread(target=self._server_thread, args=(cert_file, key_file, ca_file, port, tls_version))
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop_server(self):
        if not self.server_running:
            self.log_message("Server is not running.", "warning")
            return

        self.log_message("Stopping server...", "info")
        self.server_running = False
        
        for ssl_conn, addr in list(self.connected_clients):
            try:
                self.log_message(f"Closing connection for client {addr[0]}:{addr[1]}", "info")
                ssl_conn.shutdown()
                ssl_conn.close()
            except SSL.Error as e:
                error_details = []
                if e.args and isinstance(e.args[0], (list, tuple)) and all(isinstance(item, tuple) and len(item) == 4 for item in e.args[0]):
                    for err_code, lib, func, reason in e.args[0]:
                        error_details.append(f"  - Library: {lib}, Function: {func}, Reason: {reason}")
                    self.log_message(f"Error during SSL connection shutdown for {addr[0]}:{addr[1]}: \n{e}\nDetails:\n" + "\n".join(error_details), "error")
                else:
                    self.log_message(f"Error during SSL connection shutdown for {addr[0]}:{addr[1]}: \n{e} (No detailed OpenSSL error stack available)", "error")
            except Exception as e:
                self.log_message(f"Error closing client socket for {addr[0]}:{addr[1]}: {e}", "error")
        self.connected_clients.clear()

        if self.server_socket:
            try:
                self.server_socket.close()
                self.server_socket = None
            except OSError as e:
                self.log_message(f"Error closing server socket: {e}", "error")
        
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=2)
            if self.server_thread.is_alive():
                self.log_message("Server thread did not terminate cleanly. It might be stuck.", "warning")

        self.update_server_control_buttons() # Update buttons after stopping
        self.log_message("Server stopped.", "success")


    def _server_thread(self, cert_file, key_file, ca_file, port, tls_version):
        try:
            context = SSL.Context(SSL.TLS_SERVER_METHOD) 
            
            context.use_certificate_file(cert_file)
            context.use_privatekey_file(key_file)

            options = 0 

            if tls_version == "TLSv1.0":
                options |= SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3
            elif tls_version == "TLSv1.1":
                options |= SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1
            elif tls_version == "TLSv1.2":
                options |= SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1
            elif tls_version == "TLSv1.3":
                options |= SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1 | SSL.OP_NO_TLSv1_2
            
            context.set_options(options)
            self.log_message(f"SSL Context created with minimum TLS version: {tls_version}", "info")

            if ca_file:
                context.load_verify_locations(ca_file)
                context.set_verify(
                    SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                    self._verify_client_callback
                )
                self.log_message(f"CA Certificate loaded for client authentication: {ca_file}", "info")
            else:
                context.set_verify(SSL.VERIFY_NONE, self._verify_client_callback)
                self.log_message("No CA Certificate provided. Client authentication disabled.", "warning")

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('', port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(0.5)
            self.log_message(f"Listening for connections on port {port}...", "success")

            while self.server_running:
                try:
                    sock, addr = self.server_socket.accept()
                    self.log_message(f"Accepted connection from {addr[0]}:{addr[1]}", "info")

                    ssl_conn = SSL.Connection(context, sock)
                    ssl_conn.set_accept_state()

                    try:
                        while True:
                            try:
                                ssl_conn.do_handshake()
                                break
                            except SSL.WantReadError:
                                self.log_message(f"Handshake with {addr[0]}:{addr[1]}: Waiting for more data...", "info")
                                time.sleep(0.1)
                                continue
                            except SSL.Error as e:
                                error_details = []
                                if e.args and isinstance(e.args[0], (list, tuple)) and all(isinstance(item, tuple) and len(item) == 4 for item in e.args[0]):
                                    for err_code, lib, func, reason in e.args[0]:
                                        error_details.append(f"  - Library: {lib}, Function: {func}, Reason: {reason}")
                                    self.log_message(f"SSL Handshake failed with {addr[0]}:{addr[1]}: \n{e}\nDetails:\n" + "\n".join(error_details), "error")
                                else:
                                    self.log_message(f"SSL Handshake failed with {addr[0]}:{addr[1]}: \n{e} (No detailed OpenSSL error stack available)", "error")
                                sock.close()
                                raise
                            except Exception as e:
                                self.log_message(f"Error during handshake with {addr[0]}:{addr[1]}: \n{e}", "error")
                                sock.close()
                                raise

                        self.log_message(f"SSL Handshake successful with {addr[0]}:{addr[1]}", "success")
                        
                        negotiated_protocol = ssl_conn.get_protocol_version()
                        self.log_message(f"Negotiated Protocol: {negotiated_protocol}", "info")

                        client_cert = ssl_conn.get_peer_certificate()
                        if client_cert:
                            subject = client_cert.get_subject()
                            issuer = client_cert.get_issuer()
                            self.log_message(f"Client Certificate Subject: {subject.CN}", "info")
                            self.log_message(f"Client Certificate Issuer: {issuer.CN}", "info")
                        else:
                            self.log_message("No client certificate presented.", "info")

                        self.connected_clients.append((ssl_conn, addr))
                        self.log_message(f"Client {addr[0]}:{addr[1]} added to active connections. Total: {len(self.connected_clients)}", "info")
                        self.update_server_control_buttons() # Update buttons after a client connects

                        client_handler_thread = threading.Thread(target=self._handle_client, args=(ssl_conn, addr))
                        client_handler_thread.daemon = True
                        client_handler_thread.start()

                    except SSL.Error as e:
                        self.log_message(f"SSL Handshake failed with {addr[0]}:{addr[1]}: \n{e}", "error")
                        sock.close()
                        self.update_server_control_buttons() # Update buttons on handshake failure
                    except Exception as e:
                        self.log_message(f"Error during connection handling with {addr[0]}:{addr[1]}: \n{e}", "error")
                        sock.close()
                        self.update_server_control_buttons() # Update buttons on other connection errors

                except socket.timeout:
                    continue
                except OSError as e:
                    if self.server_running: 
                        self.log_message(f"Socket error (likely server shutdown): \n{e}", "error")
                    break
                except Exception as e:
                    self.log_message(f"Unexpected error in server accept loop: \n{e}", "error")
                    if not self.server_running: 
                        break

        except SSL.Error as e:
            self.log_message(f"SSL Context or Certificate Error: \n{e}", "error")
            self.stop_server()
        except socket.error as e:
            self.log_message(f"Socket Binding Error: \n{e}. Is the port already in use?", "error")
            self.stop_server()
        except Exception as e:
            self.log_message(f"Unhandled Server Thread Error: {e}", "error")
            self.stop_server()
        finally:
            if self.server_socket:
                try:
                    self.server_socket.close()
                except OSError as e:
                    self.log_message(f"Error during final server socket close: {e}", "error")
                self.server_socket = None
            self.server_running = False # Ensure server_running is False
            self.update_server_control_buttons() # Final update when server thread terminates
            self.log_message("Server thread terminated.", "info")

    def _handle_client(self, ssl_conn, addr):
        while self.server_running:
            try:
                data = ssl_conn.recv(4096)
                if not data:
                    self.log_message(f"Client {addr[0]}:{addr[1]} initiated clean SSL shutdown or closed the connection.", "info")
                    break
                self.log_message(f"Received from {addr[0]}:{addr[1]}: {data.decode('utf-8', errors='ignore')}", "received")
                response = f"Echo from server: {data.decode('utf-8', errors='ignore')}"
                
                response_bytes = response.encode('utf-8')
                while True:
                    try:
                        ssl_conn.sendall(response_bytes)
                        break
                    except SSL.WantWriteError:
                        self.log_message(f"Send to {addr[0]}:{addr[1]}: Waiting for write buffer to clear...", "info")
                        time.sleep(0.05)
                        continue

                self.log_message(f"Sent echo to {addr[0]}:{addr[1]}: {response}", "sent")
            except SSL.WantReadError:
                time.sleep(0.05)
                continue
            except SSL.ZeroReturnError:
                self.log_message(f"Client {addr[0]}:{addr[1]} initiated clean SSL shutdown (ZeroReturnError).", "info")
                break
            except SSL.Error as e:
                error_details = []
                if e.args and isinstance(e.args[0], (list, tuple)) and all(isinstance(item, tuple) and len(item) == 4 for item in e.args[0]):
                    for err_code, lib, func, reason in e.args[0]:
                        error_details.append(f"  - Library: {lib}, Function: {func}, Reason: {reason}")
                    self.log_message(f"SSL data error with {addr[0]}:{addr[1]}: \n{e}\nDetails:\n" + "\n".join(error_details), "error")
                else:
                    self.log_message(f"SSL data error with {addr[0]}:{addr[1]}: \n{e} \n(No detailed OpenSSL error stack available)", "error")
                break
            except socket.error as e:
                if e.errno == 10035:
                    time.sleep(0.05)
                    continue
                elif e.errno == 10054:
                    self.log_message(f"Socket error with {addr[0]}:{addr[1]} \n(Connection Reset by Peer): \n{e}", "error")
                else:
                    self.log_message(f"Socket error with {addr[0]}:{addr[1]}: \n{e}", "error")
                break
            except Exception as e:
                self.log_message(f"Unexpected error during data exchange with {addr[0]}:{addr[1]}: \n{e}", "error")
                break
        
        if (ssl_conn, addr) in self.connected_clients:
            self.connected_clients.remove((ssl_conn, addr))
            self.log_message(f"Client {addr[0]}:{addr[1]} removed from active connections. Total: {len(self.connected_clients)}", "info")
        try:
            ssl_conn.shutdown()
            ssl_conn.close()
            self.log_message(f"Connection with {addr[0]}:{addr[1]} closed.", "info")
        except SSL.Error as e:
            error_details = []
            if e.args and isinstance(e.args[0], (list, tuple)) and all(isinstance(item, tuple) and len(item) == 4 for item in e.args[0]):
                for err_code, lib, func, reason in e.args[0]:
                    error_details.append(f"  - Library: {lib}, Function: {func}, Reason: {reason}")
                self.log_message(f"Error closing SSL connection for {addr[0]}:{addr[1]}: {e}\nDetails:\n" + "\n".join(error_details), "error")
            else:
                self.log_message(f"Error closing SSL connection for {addr[0]}:{addr[1]}: {e} (No detailed OpenSSL error stack available)", "error")
        except Exception as e:
            self.log_message(f"Error closing socket for {addr[0]}:{addr[1]}: {e}", "error")
        
        # After a client is removed, check if any clients are still connected.
        # If no clients are connected and the server is still theoretically running (listening),
        # then re-enable the start button and disable the stop button.
        if not self.connected_clients and self.server_running:
            self.update_server_control_buttons()


    def send_message_event(self, event=None):
        self.send_message()

    def send_message(self):
        if not self.server_running:
            self.log_message("Server is not running. Cannot send message.", "warning")
            return
        
        message = self.message_entry.get()
        if not message:
            self.log_message("Cannot send empty message.", "warning")
            return

        if not self.connected_clients:
            self.log_message("No clients connected to send message.", "warning")
            self.message_entry.delete(0, tk.END)
            # No clients, so update buttons
            self.update_server_control_buttons()
            return

        message_bytes = message.encode('utf-8')
        clients_to_remove = []

        self.log_message(f"Attempting to send message to {len(self.connected_clients)} client(s): '{message}'", "info")
        for ssl_conn, addr in list(self.connected_clients):
            try:
                while True:
                    try:
                        ssl_conn.sendall(message_bytes)
                        break
                    except SSL.WantWriteError:
                        self.log_message(f"Send to {addr[0]}:{addr[1]}: Waiting for write buffer to clear...", "info")
                        time.sleep(0.05)
                        continue
            except SSL.Error as e:
                error_details = []
                if e.args and isinstance(e.args[0], (list, tuple)) and all(isinstance(item, tuple) and len(item) == 4 for item in e.args[0]):
                    for err_code, lib, func, reason in e.args[0]:
                        error_details.append(f"  - Library: {lib}, Function: {func}, Reason: {reason}")
                    self.log_message(f"SSL send error to {addr[0]}:{addr[1]}: \n{e}\nDetails:\n" + "\n".join(error_details), "error")
                else:
                    self.log_message(f"SSL send error to {addr[0]}:{addr[1]}: \n{e} (No detailed OpenSSL error stack available)", "error")
                clients_to_remove.append((ssl_conn, addr))
            except socket.error as e:
                self.log_message(f"Socket send error to {addr[0]}:{addr[1]}: \n{e}. Client will be disconnected.", "error")
                clients_to_remove.append((ssl_conn, addr))
            except Exception as e:
                self.log_message(f"Unexpected error sending to {addr[0]}:{addr[1]}: \n{e}. Client will be disconnected.", "error")
                clients_to_remove.append((ssl_conn, addr))
            else:
                self.log_message(f"Sent to {addr[0]}:{addr[1]}: {message}", "sent")
        
        for client_info in clients_to_remove:
            if client_info in self.connected_clients:
                self.connected_clients.remove(client_info)
                self.log_message(f"Client {client_info[1][0]}:{client_info[1][1]} removed due to send error.", "info")
                try:
                    client_info[0].shutdown()
                    client_info[0].close()
                except SSL.Error as e:
                    error_details = []
                    if e.args and isinstance(e.args[0], (list, tuple)) and all(isinstance(item, tuple) and len(item) == 4 for item in e.args[0]):
                        for err_code, lib, func, reason in e.args[0]:
                            error_details.append(f"  - Library: {lib}, Function: {func}, Reason: {reason}")
                        self.log_message(f"Error closing SSL connection for removed client {client_info[1][0]}:{client_info[1][1]}: \n{e}\nDetails:\n" + "\n".join(error_details), "error")
                    else:
                        self.log_message(f"Error closing SSL connection for removed client {client_info[1][0]}:{client_info[1][1]}: \n{e} (No detailed OpenSSL error stack available)", "error")
                except Exception as e:
                    self.log_message(f"Error closing socket for removed client {client_info[1][0]}:{client_info[1][1]}: \n{e}", "error")

        self.message_entry.delete(0, tk.END)
        # After attempting to send to all clients and potentially removing some, update button states.
        self.update_server_control_buttons()


    def _verify_client_callback(self, conn, cert, errnum, depth, preverify_ok):
        if cert:
            subject = cert.get_subject()
            issuer = cert.get_issuer()
            self.log_message(f"Verifying client cert: Subject={subject.CN}, Issuer={issuer.CN}, Depth={depth}", "info")
        else:
            self.log_message(f"Verifying client cert: No cert presented at depth {depth}", "info")

        if not preverify_ok:
            self.log_message(f"Client cert verification failed: {SSL.Error(errnum).args[0]}", "error")
            return False

        self.log_message(f"Client cert pre-verification OK: {preverify_ok}", "info")
        return preverify_ok

    def on_closing(self):
        if self.server_running:
            self.stop_server()
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = TLSServerApp(root)
    root.mainloop()