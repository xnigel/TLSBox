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

import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext
import socket
import threading
import os
from OpenSSL import SSL, crypto

class TLSServerApp:
    def __init__(self, master):
        self.master = master
        Server_ver = "00.01.00"
        Server_yr = "2025.07.28"
        master.title("TLS Server" + " (v" + Server_ver +")" + " - " + Server_yr + " - nigel.zhai@ul.com")
        master.geometry("500x700") # Increased height for new section
        master.minsize(500, 700) # Set minimum window size
        master.maxsize(500, 700)
        master.resizable(True, True) # Allow resizing

        self.server_running = False
        self.server_socket = None
        self.server_thread = None
        self.connected_clients = [] # List to keep track of active SSL connections and their addresses

        # --- Configuration Frame ---
        config_frame = ttk.LabelFrame(master, text="Server Configuration", padding="10")
        config_frame.pack(padx=10, pady=10, fill="x", expand=False)

        # File paths
        self.cert_file_var = tk.StringVar()
        self.key_file_var = tk.StringVar()
        self.ca_file_var = tk.StringVar()
        self.port_var = tk.StringVar(value="443")
        self.tls_version_var = tk.StringVar(value="TLSv1.2") # Default to TLSv1.2

        # Grid layout for configuration
        row = 0
        ttk.Label(config_frame, text="Server Certificate:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(config_frame, textvariable=self.cert_file_var, width=50).grid(row=row, column=1, padx=5, pady=2, sticky="ew")
        ttk.Button(config_frame, text="Browse", command=lambda: self.browse_file(self.cert_file_var, "*.pem")).grid(row=row, column=2, pady=2)

        row += 1
        ttk.Label(config_frame, text="Server Private Key:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(config_frame, textvariable=self.key_file_var, width=50).grid(row=row, column=1, padx=5, pady=2, sticky="ew")
        ttk.Button(config_frame, text="Browse", command=lambda: self.browse_file(self.key_file_var, "*.key")).grid(row=row, column=2, pady=2)

        row += 1
        ttk.Label(config_frame, text="CA Certificate:").grid(row=row, column=0, sticky="w", pady=2) # (PEM - for client auth)
        ttk.Entry(config_frame, textvariable=self.ca_file_var, width=50).grid(row=row, column=1, padx=5, pady=2, sticky="ew")
        ttk.Button(config_frame, text="Browse", command=lambda: self.browse_file(self.ca_file_var, "*.pem")).grid(row=row, column=2, pady=2)

        row += 1
        ttk.Label(config_frame, text="Port:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(config_frame, textvariable=self.port_var, width=10).grid(row=row, column=1, padx=5, pady=2, sticky="w")

        row += 1
        ttk.Label(config_frame, text="Minimum TLS Version:").grid(row=row, column=0, sticky="w", pady=2)
        tls_versions = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
        self.tls_version_combobox = ttk.Combobox(config_frame, textvariable=self.tls_version_var, values=tls_versions, state="readonly", width=15)
        self.tls_version_combobox.grid(row=row, column=1, padx=5, pady=2, sticky="w")
        self.tls_version_combobox.set("TLSv1.2") # Set default value

        config_frame.columnconfigure(1, weight=1) # Make the entry fields expand

        # --- Control Buttons ---
        button_frame = ttk.Frame(master, padding="10")
        button_frame.pack(padx=10, pady=5, fill="x", expand=False)

        # Adding colours to buttons
        self.start_button = ttk.Button(button_frame, text="Start Server", command=self.start_server)
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Server", command=self.stop_server, state="disabled")
        self.stop_button.pack(side="left", padx=5)
        
        # --- Message Input (New Section) ---
        message_frame = ttk.LabelFrame(master, text="Send Message to Clients", padding="10")
        message_frame.pack(padx=10, pady=5, fill="x", expand=False)

        self.message_entry = ttk.Entry(message_frame, width=50)
        self.message_entry.pack(side="left", padx=5, fill="x", expand=True)
        self.message_entry.bind("<Return>", self.send_message_event) # Bind Enter key

        self.send_button = ttk.Button(message_frame, text="Send", command=self.send_message, state="disabled")
        self.send_button.pack(side="left", padx=5)


        # --- Log Area ---
        log_frame = ttk.LabelFrame(master, text="Server Log", padding="10")
        log_frame.pack(padx=10, pady=10, fill="both", expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state="disabled", width=80, height=20)
        self.log_text.pack(fill="both", expand=True)

        # Configure styling
        style = ttk.Style()
        style.configure("TLabel", font=("Inter", 10))
        style.configure("TButton", font=("Inter", 10, "bold"))
        style.configure("TEntry", font=("Inter", 10))
        style.configure("TCombobox", font=("Inter", 10))
        style.configure("TLabelFrame", font=("Inter", 11, "bold"))
        self.log_text.tag_configure("info", foreground="blue")
        self.log_text.tag_configure("success", foreground="green")
        self.log_text.tag_configure("error", foreground="red")
        self.log_text.tag_configure("warning", foreground="orange")
        self.log_text.tag_configure("sent", foreground="darkgreen") # New tag for sent messages
        self.log_text.tag_configure("received", foreground="purple") # New tag for received messages

        master.protocol("WM_DELETE_WINDOW", self.on_closing) # Handle window close event

    def browse_file(self, var, file_types):
        """Opens a file dialog and sets the selected file path to the given StringVar."""
        file_path = filedialog.askopenfilename(filetypes=[("PEM files", file_types), ("All files", "*.*")])
        if file_path:
            var.set(file_path)

    def log_message(self, message, tag="info"):
        """Logs a message to the scrolled text widget."""
        self.master.after(0, lambda: self._insert_log_message(message, tag))

    def _insert_log_message(self, message, tag):
        """Internal method to safely insert log messages from any thread."""
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def start_server(self):
        """Starts the TLS server in a new thread."""
        if self.server_running:
            self.log_message("Server is already running.", "warning")
            return

        cert_file = self.cert_file_var.get()
        key_file = self.key_file_var.get()
        ca_file = self.ca_file_var.get()
        port_str = self.port_var.get()
        tls_version = self.tls_version_var.get()

        # Input validation
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
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.send_button.config(state="normal") # Enable send button when server starts
        self.log_message(f"Attempting to start server on port {port} with minimum TLS version {tls_version}...", "info")

        # Start server in a separate thread
        self.server_thread = threading.Thread(target=self._server_thread, args=(cert_file, key_file, ca_file, port, tls_version))
        self.server_thread.daemon = True # Allow the main program to exit even if thread is running
        self.server_thread.start()

    def stop_server(self):
        """Stops the TLS server."""
        if not self.server_running:
            self.log_message("Server is not running.", "warning")
            return

        self.log_message("Stopping server...", "info")
        self.server_running = False
        
        # Close all connected client SSL connections
        for ssl_conn, addr in list(self.connected_clients): # Iterate over a copy
            try:
                self.log_message(f"Closing connection for client {addr[0]}:{addr[1]}", "info")
                ssl_conn.shutdown()
                ssl_conn.close()
            except SSL.Error as e:
                self.log_message(f"Error during SSL connection shutdown for {addr[0]}:{addr[1]}: {e}", "error")
            except Exception as e:
                self.log_message(f"Error closing client socket for {addr[0]}:{addr[1]}: {e}", "error")
        self.connected_clients.clear() # Clear the list after attempting to close all

        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
                self.server_socket.close()
                self.server_socket = None
            except OSError as e:
                self.log_message(f"Error closing server socket: {e}", "error")
        
        # Wait for the server thread to finish if it's still alive
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=2) # Give it a moment to clean up
            if self.server_thread.is_alive():
                self.log_message("Server thread did not terminate cleanly. It might be stuck.", "warning")

        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.send_button.config(state="disabled") # Disable send button when server stops
        self.log_message("Server stopped.", "success")

    def _server_thread(self, cert_file, key_file, ca_file, port, tls_version):
        """
        The main server logic running in a separate thread.
        Handles SSL context creation, socket binding, and client connections.
        """
        try:
            # Create SSL context
            context = SSL.Context(SSL.TLS_SERVER_METHOD) 
            
            # Load server certificate and private key
            context.use_certificate_file(cert_file)
            context.use_privatekey_file(key_file)

            # Set TLS protocol options based on user selection
            options = 0 

            if tls_version == "TLSv1.0":
                options |= SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3
            elif tls_version == "TLSv1.1":
                options |= SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1
            elif tls_version == "TLSv1.2":
                options |= SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1 | SSL.OP_NO_TLSv1_3
            elif tls_version == "TLSv1.3":
                options |= SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1 | SSL.OP_NO_TLSv1_2
            
            context.set_options(options)
            self.log_message(f"SSL Context created with minimum TLS version: {tls_version}", "info")

            # Load CA certificate for client authentication if provided
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

            # Create a standard socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('', port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(0.5) # Set a small timeout for accept to allow graceful shutdown
            self.log_message(f"Listening for connections on port {port}...", "success")

            while self.server_running:
                try:
                    # Accept a new connection
                    sock, addr = self.server_socket.accept()
                    self.log_message(f"Accepted connection from {addr[0]}:{addr[1]}", "info")

                    # Wrap the socket with SSL
                    ssl_conn = SSL.Connection(context, sock)
                    ssl_conn.set_accept_state()

                    try:
                        # Perform the SSL handshake
                        ssl_conn.do_handshake()
                        self.log_message(f"SSL Handshake successful with {addr[0]}:{addr[1]}", "success")
                        
                        # Get negotiated protocol version
                        negotiated_protocol = ssl_conn.get_protocol_version()
                        self.log_message(f"Negotiated Protocol: {negotiated_protocol}", "info")

                        # Get client certificate if available
                        client_cert = ssl_conn.get_peer_certificate()
                        if client_cert:
                            subject = client_cert.get_subject()
                            issuer = client_cert.get_issuer()
                            self.log_message(f"Client Certificate Subject: {subject.CN}", "info")
                            self.log_message(f"Client Certificate Issuer: {issuer.CN}", "info")
                        else:
                            self.log_message("No client certificate presented.", "info")

                        # Add the new client to the list of connected clients
                        self.connected_clients.append((ssl_conn, addr))
                        self.log_message(f"Client {addr[0]}:{addr[1]} added to active connections. Total: {len(self.connected_clients)}", "info")

                        # Handle data exchange for this client in a new thread
                        client_handler_thread = threading.Thread(target=self._handle_client, args=(ssl_conn, addr))
                        client_handler_thread.daemon = True
                        client_handler_thread.start()

                    except SSL.Error as e:
                        self.log_message(f"SSL Handshake failed with {addr[0]}:{addr[1]}: {e}", "error")
                        sock.close() # Close raw socket if handshake fails
                    except Exception as e:
                        self.log_message(f"Error during connection handling with {addr[0]}:{addr[1]}: {e}", "error")
                        sock.close() # Close raw socket on error

                except socket.timeout:
                    # This is expected when no connections are incoming, allows checking self.server_running
                    continue
                except OSError as e:
                    if self.server_running: 
                        self.log_message(f"Socket error (likely server shutdown): {e}", "error")
                    break # Break the loop if server socket is closed
                except Exception as e:
                    self.log_message(f"Unexpected error in server accept loop: {e}", "error")
                    if not self.server_running: 
                        break

        except SSL.Error as e:
            self.log_message(f"SSL Context or Certificate Error: {e}", "error")
            self.stop_server()
        except socket.error as e:
            self.log_message(f"Socket Binding Error: {e}. Is the port already in use?", "error")
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
            self.server_running = False
            self.master.after(0, lambda: self.start_button.config(state="normal"))
            self.master.after(0, lambda: self.stop_button.config(state="disabled"))
            self.master.after(0, lambda: self.send_button.config(state="disabled"))
            self.log_message("Server thread terminated.", "info")

    def _handle_client(self, ssl_conn, addr):
        """Handles data reception for a single connected client."""
        while self.server_running:
            try:
                data = ssl_conn.recv(4096)
                if not data:
                    self.log_message(f"Client {addr[0]}:{addr[1]} disconnected.", "info")
                    break # Exit loop if client disconnected
                self.log_message(f"Received from {addr[0]}:{addr[1]}: {data.decode('utf-8', errors='ignore')}", "received")
                # Echo back the data (original functionality)
                response = f"Echo from server: {data.decode('utf-8', errors='ignore')}"
                ssl_conn.sendall(response.encode('utf-8'))
                self.log_message(f"Sent echo to {addr[0]}:{addr[1]}: {response}", "sent")
            except SSL.WantReadError:
                # No data available, continue loop
                continue
            except SSL.Error as e:
                self.log_message(f"SSL data error with {addr[0]}:{addr[1]}: {e}", "error")
                break
            except socket.error as e:
                self.log_message(f"Socket error with {addr[0]}:{addr[1]}: {e}", "error")
                break
            except Exception as e:
                self.log_message(f"Unexpected error during data exchange with {addr[0]}:{addr[1]}: {e}", "error")
                break
        
        # Client disconnected or error, remove from active list and close
        if (ssl_conn, addr) in self.connected_clients:
            self.connected_clients.remove((ssl_conn, addr))
            self.log_message(f"Client {addr[0]}:{addr[1]} removed from active connections. Total: {len(self.connected_clients)}", "info")
        try:
            ssl_conn.shutdown()
            ssl_conn.close()
            self.log_message(f"Connection with {addr[0]}:{addr[1]} closed.", "info")
        except Exception as e:
            self.log_message(f"Error closing SSL connection for {addr[0]}:{addr[1]}: {e}", "error")

    def send_message_event(self, event=None):
        """Handler for sending message when Enter key is pressed."""
        self.send_message()

    def send_message(self):
        """Sends a message from the server to all connected TLS clients."""
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
            return

        message_bytes = message.encode('utf-8')
        clients_to_remove = []

        self.log_message(f"Attempting to send message to {len(self.connected_clients)} client(s): '{message}'", "info")
        for ssl_conn, addr in self.connected_clients:
            try:
                ssl_conn.sendall(message_bytes)
                self.log_message(f"Sent to {addr[0]}:{addr[1]}: {message}", "sent")
            except SSL.Error as e:
                self.log_message(f"SSL send error to {addr[0]}:{addr[1]}: {e}. Client will be disconnected.", "error")
                clients_to_remove.append((ssl_conn, addr))
            except socket.error as e:
                self.log_message(f"Socket send error to {addr[0]}:{addr[1]}: {e}. Client will be disconnected.", "error")
                clients_to_remove.append((ssl_conn, addr))
            except Exception as e:
                self.log_message(f"Unexpected error sending to {addr[0]}:{addr[1]}: {e}. Client will be disconnected.", "error")
                clients_to_remove.append((ssl_conn, addr))
        
        # Remove clients that had errors during send
        for client_info in clients_to_remove:
            if client_info in self.connected_clients:
                self.connected_clients.remove(client_info)
                self.log_message(f"Client {client_info[1][0]}:{client_info[1][1]} removed due to send error.", "info")
                try:
                    client_info[0].shutdown()
                    client_info[0].close()
                except Exception as e:
                    self.log_message(f"Error closing socket for removed client {client_info[1][0]}:{client_info[1][1]}: {e}", "error")

        self.message_entry.delete(0, tk.END) # Clear the input field


    def _verify_client_callback(self, conn, cert, errnum, depth, preverify_ok):
        """
        Callback function for client certificate verification.
        Logs details about the client certificate and verification status.
        """
        if cert:
            subject = cert.get_subject()
            issuer = cert.get_issuer()
            self.log_message(f"Verifying client cert: Subject={subject.CN}, Issuer={issuer.CN}, Depth={depth}", "info")
        else:
            self.log_message(f"Verifying client cert: No cert presented at depth {depth}", "info")

        if not preverify_ok:
            self.log_message(f"Client cert verification failed: {SSL.Error(errnum).args[0]}", "error")
            return False # Reject connection if verification fails

        self.log_message(f"Client cert pre-verification OK: {preverify_ok}", "info")
        return preverify_ok

    def on_closing(self):
        """Handles the window closing event to ensure server is stopped."""
        if self.server_running:
            self.stop_server()
        self.master.destroy()

if __name__ == "__main__":
    # To run this code, you'll need server-cert.pem, server-cert.key, and optionally ca-cert.pem.
    # You can generate them using OpenSSL commands:

    # 1. Generate CA private key and certificate (for client auth)
    # openssl genrsa -out ca-cert.key 2048
    # openssl req -x509 -new -nodes -key ca-cert.key -sha256 -days 365 -out ca-cert.pem -subj "/CN=MyTestCA"

    # 2. Generate server private key and certificate signing request (CSR)
    # openssl genrsa -out server-cert.key 2048
    # openssl req -new -key server-cert.key -out server-cert.csr -subj "/CN=localhost"

    # 3. Sign the server CSR with your CA (for client auth)
    # openssl x509 -req -in server-cert.csr -CA ca-cert.pem -CAkey ca-cert.key -CAcreateserial -out server-cert.pem -days 365 -sha256

    # If you don't need client authentication, you can generate a self-signed server certificate:
    # openssl req -x509 -newkey rsa:2048 -keyout server-cert.key -out server-cert.pem -days 365 -nodes -subj "/CN=localhost"

    root = tk.Tk()
    app = TLSServerApp(root)
    root.mainloop()
