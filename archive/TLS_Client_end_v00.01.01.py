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

class TLSClientApp:
    def __init__(self, master):
        self.master = master
        Client_ver = "00.01.00"
        Client_yr = "2025.07.28"
        master.title("TLS Client" + " (v" + Client_ver +")" + " - " + Client_yr + " - nigel.zhai@ul.com")
        master.geometry("500x650")
        master.minsize(500, 700) # Set minimum window size
        master.maxsize(500, 700)
        master.resizable(True, True) # Allow resizing

        self.client_connected = False
        self.ssl_conn = None
        self.client_socket = None
        self.client_thread = None

        # --- Configuration Frame ---
        config_frame = ttk.LabelFrame(master, text="Client Configuration", padding="5")
        config_frame.pack(padx=5, pady=10, fill="x", expand=False)

        # Connection details
        self.ip_var = tk.StringVar(value="192.168.1.104")
        self.port_var = tk.StringVar(value="443")

        # File paths for client certificates
        self.cert_file_var = tk.StringVar()
        self.key_file_var = tk.StringVar()
        self.ca_file_var = tk.StringVar()
        self.tls_version_var = tk.StringVar(value="TLSv1.2") # Default to TLSv1.2

        # Grid layout for configuration
        row = 0

        row += 1
        ttk.Label(config_frame, text="Client Certificate:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(config_frame, textvariable=self.cert_file_var, width=50).grid(row=row, column=1, padx=5, pady=2, sticky="ew")
        ttk.Button(config_frame, text="Browse", command=lambda: self.browse_file(self.cert_file_var, "*.pem")).grid(row=row, column=2, pady=2)

        row += 1
        ttk.Label(config_frame, text="Client/Private Key:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(config_frame, textvariable=self.key_file_var, width=50).grid(row=row, column=1, padx=5, pady=2, sticky="ew")
        ttk.Button(config_frame, text="Browse", command=lambda: self.browse_file(self.key_file_var, "*.key")).grid(row=row, column=2, pady=2)

        row += 1
        ttk.Label(config_frame, text="CA Certificate:").grid(row=row, column=0, sticky="w", pady=2) # (PEM - for server cert verification)
        ttk.Entry(config_frame, textvariable=self.ca_file_var, width=50).grid(row=row, column=1, padx=5, pady=2, sticky="ew")
        ttk.Button(config_frame, text="Browse", command=lambda: self.browse_file(self.ca_file_var, "*.pem")).grid(row=row, column=2, pady=2)

        row += 1
        ttk.Label(config_frame, text="Destination IP:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(config_frame, textvariable=self.ip_var, width=20).grid(row=row, column=1, padx=5, pady=2, sticky="w")
        row += 1
        ttk.Label(config_frame, text="Destination Port:").grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(config_frame, textvariable=self.port_var, width=10).grid(row=row, column=1, padx=5, pady=2, sticky="w")

        row += 1
        ttk.Label(config_frame, text="TLS Version:").grid(row=row, column=0, sticky="w", pady=2)
        tls_versions = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
        self.tls_version_combobox = ttk.Combobox(config_frame, textvariable=self.tls_version_var, values=tls_versions, state="readonly", width=15)
        self.tls_version_combobox.grid(row=row, column=1, padx=5, pady=2, sticky="w")
        self.tls_version_combobox.set("TLSv1.2") # Set default value

        config_frame.columnconfigure(1, weight=1) # Make the entry fields expand

        # --- Control Buttons ---
        button_frame = ttk.Frame(master, padding="5")
        button_frame.pack(padx=5, pady=5, fill="x", expand=False)

        self.connect_button = ttk.Button(button_frame, text="Connect", command=self.connect_client, style="Green.TButton")
        self.connect_button.pack(side="left", padx=5)

        self.disconnect_button = ttk.Button(button_frame, text="Disconnect", command=self.disconnect_client, state="disabled", style="Red.TButton")
        self.disconnect_button.pack(side="left", padx=5)

        # --- Message Input ---
        message_frame = ttk.LabelFrame(master, text="Send Message to Servers", padding="5")
        message_frame.pack(padx=5, pady=5, fill="x", expand=False)

        self.message_entry = ttk.Entry(message_frame, width=50)
        self.message_entry.pack(side="left", padx=5, fill="x", expand=True)
        self.message_entry.bind("<Return>", self.send_message_event) # Bind Enter key

        self.send_button = ttk.Button(message_frame, text="Send", command=self.send_message, state="disabled")
        self.send_button.pack(side="left", padx=5)

        # --- Log Area ---
        log_frame = ttk.LabelFrame(master, text="Client Log", padding="5")
        log_frame.pack(padx=5, pady=10, fill="both", expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state="disabled", width=80, height=20)
        self.log_text.pack(fill="both", expand=True)

        # Configure styling
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

        # Custom button styles
        style.configure("Green.TButton", background="#D1FFBD", foreground="black")
        style.map("Green.TButton",
                  background=[("active", "darkgreen"), ("disabled", "lightgray")],
                  foreground=[("active", "white"), ("disabled", "darkgray")])

        style.configure("Red.TButton", background="#FF5C5C", foreground="black")
        style.map("Red.TButton",
                  background=[("active", "darkred"), ("disabled", "lightgray")],
                  foreground=[("active", "white"), ("disabled", "darkgray")])
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

    def connect_client(self):
        """Initiates the TLS client connection in a new thread."""
        if self.client_connected:
            self.log_message("Client is already connected.", "warning")
            return

        ip_address = self.ip_var.get()
        port_str = self.port_var.get()
        cert_file = self.cert_file_var.get()
        key_file = self.key_file_var.get()
        ca_file = self.ca_file_var.get()
        tls_version = self.tls_version_var.get()

        # Input validation
        if not ip_address:
            self.log_message("Error: Destination IP address is required.", "error")
            return
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            self.log_message("Error: Invalid port number. Please enter a number between 1 and 65535.", "error")
            return

        # Validate certificate/key files if provided
        if cert_file and not os.path.exists(cert_file):
            self.log_message(f"Error: Client Certificate file not found: {cert_file}", "error")
            return
        if key_file and not os.path.exists(key_file):
            self.log_message(f"Error: Private key file not found: {key_file}", "error")
            return
        if ca_file and not os.path.exists(ca_file):
            self.log_message(f"Error: CA Certificate file not found: {ca_file}", "error")
            return
        
        # If cert file is provided, key file must also be provided
        if bool(cert_file) != bool(key_file):
            self.log_message("Error: Both Client Certificate and Private Key must be provided if either is specified.", "error")
            return

        self.log_message(f"Attempting to connect to {ip_address}:{port} with minimum TLS version {tls_version}...", "info")
        self.connect_button.config(state="disabled")
        self.disconnect_button.config(state="normal")
        self.send_button.config(state="disabled") # Disable send until connected

        # Start client connection in a separate thread
        self.client_thread = threading.Thread(target=self._client_thread, args=(ip_address, port, cert_file, key_file, ca_file, tls_version))
        self.client_thread.daemon = True # Allow the main program to exit even if thread is running
        self.client_thread.start()

    def disconnect_client(self):
        """Disconnects the TLS client."""
        if not self.client_connected:
            self.log_message("Client is not connected.", "warning")
            return

        self.log_message("Disconnecting client...", "info")
        self.client_connected = False
        if self.ssl_conn:
            try:
                self.ssl_conn.shutdown()
                self.ssl_conn.close()
            except SSL.Error as e:
                self.log_message(f"Error during SSL connection shutdown: {e}", "error")
            self.ssl_conn = None
        if self.client_socket:
            try:
                self.client_socket.close()
            except OSError as e:
                self.log_message(f"Error closing client socket: {e}", "error")
            self.client_socket = None
        
        # Wait for the client thread to finish if it's still alive
        if self.client_thread and self.client_thread.is_alive():
            self.client_thread.join(timeout=2) # Give it a moment to clean up
            if self.client_thread.is_alive():
                self.log_message("Client thread did not terminate cleanly. It might be stuck.", "warning")

        self.connect_button.config(state="normal")
        self.disconnect_button.config(state="disabled")
        self.send_button.config(state="disabled")
        self.log_message("Client disconnected.", "success")

    def _client_thread(self, ip_address, port, cert_file, key_file, ca_file, tls_version):
        """
        The main client logic running in a separate thread.
        Handles SSL context creation, socket connection, and data exchange.
        """
        try:
            # Create SSL context for client
            context = SSL.Context(SSL.TLS_CLIENT_METHOD)

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

            # Load client certificate and private key if provided (for client authentication)
            if cert_file and key_file:
                context.use_certificate_file(cert_file)
                context.use_privatekey_file(key_file)
                self.log_message(f"Client Certificate loaded: {cert_file}", "info")
            else:
                self.log_message("No client certificate provided. Client authentication will not be attempted.", "warning")

            # Load CA certificate for server certificate verification
            if ca_file:
                context.load_verify_locations(ca_file)
                context.set_verify(SSL.VERIFY_PEER, self._verify_server_callback)
                self.log_message(f"CA Certificate loaded for server verification: {ca_file}", "info")
            else:
                context.set_verify(SSL.VERIFY_NONE, self._verify_server_callback)
                self.log_message("No CA Certificate provided. Server certificate will not be verified.", "warning")

            # Create a standard socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5) # Set a timeout for connection attempts

            # Connect to the server
            self.client_socket.connect((ip_address, port))
            self.log_message(f"Connected to {ip_address}:{port}", "success")
            self.log_message(f"Nigel: good_1?")

            # Wrap the socket with SSL
            self.ssl_conn = SSL.Connection(context, self.client_socket)
            self.ssl_conn.set_connect_state()
            self.log_message(f"Nigel: good_2?")

            # Perform the SSL handshake
            self.ssl_conn.do_handshake()
            self.log_message("SSL Handshake successful!", "success")
            self.log_message(f"Negotiated Protocol: {self.ssl_conn.get_protocol_version()}", "info")

            # Get server certificate details
            server_cert = self.ssl_conn.get_peer_certificate()
            if server_cert:
                subject = server_cert.get_subject()
                issuer = server_cert.get_issuer()
                self.log_message(f"Server Certificate Subject: {subject.CN}", "info")
                self.log_message(f"Server Certificate Issuer: {issuer.CN}", "info")
            else:
                self.log_message("No server certificate presented.", "info")

            self.client_connected = True
            self.master.after(0, lambda: self.send_button.config(state="normal")) # Enable send button

            # Start receiving data in a sub-thread
            self.receive_thread = threading.Thread(target=self._receive_data_thread)
            self.receive_thread.daemon = True
            self.receive_thread.start()

        except socket.timeout:
            print(f"Connection timed out to {ip_address}:{port}")
            self.log_message(f"Connection timed out to {ip_address}:{port}", "error")
            self.disconnect_client()
        except socket.error as e:
            print(f"Socket Error: {e}")
            self.log_message(f"Socket Error: {e}", "error")
            self.disconnect_client()
        except SSL.Error as e:
            print(f"SSL Handshake Error: {e}")
            self.log_message(f"SSL Handshake Error: {e}", "error")
            self.disconnect_client()
        except Exception as e:
            print(f"Unhandled Client Thread Error: {e}")
            self.log_message(f"Unhandled Client Thread Error: {e}", "error")
            self.disconnect_client()
        finally:
            # Ensure buttons are re-enabled if connection fails
            if not self.client_connected:
                self.master.after(0, lambda: self.connect_button.config(state="normal"))
                self.master.after(0, lambda: self.disconnect_button.config(state="disabled"))
                self.master.after(0, lambda: self.send_button.config(state="disabled"))

    def _receive_data_thread(self):
        """Thread to continuously receive data from the server."""
        while self.client_connected:
            try:
                data = self.ssl_conn.recv(4096)
                if not data:
                    self.log_message("Server closed the connection.", "info")
                    self.disconnect_client()
                    break
                self.log_message(f"Received: {data.decode('utf-8', errors='ignore')}", "received")
            except SSL.WantReadError:
                # No data available, continue loop
                continue
            except SSL.Error as e:
                self.log_message(f"SSL receive error: {e}", "error")
                self.disconnect_client()
                break
            except socket.error as e:
                self.log_message(f"Socket receive error: {e}", "error")
                self.disconnect_client()
                break
            except Exception as e:
                self.log_message(f"Unexpected error in receive thread: {e}", "error")
                self.disconnect_client()
                break

    def send_message_event(self, event=None):
        """Handler for sending message when Enter key is pressed."""
        self.send_message()

    def send_message(self):
        """Sends a message to the connected TLS server."""
        if not self.client_connected or not self.ssl_conn:
            self.log_message("Not connected to a server.", "warning")
            return

        message = self.message_entry.get()
        if not message:
            self.log_message("Cannot send empty message.", "warning")
            return

        try:
            self.ssl_conn.sendall(message.encode('utf-8'))
            self.log_message(f"Sent: {message}", "sent")
            self.message_entry.delete(0, tk.END) # Clear the input field
        except SSL.Error as e:
            self.log_message(f"SSL send error: {e}", "error")
            self.disconnect_client()
        except socket.error as e:
            self.log_message(f"Socket send error: {e}", "error")
            self.disconnect_client()
        except Exception as e:
            self.log_message(f"Unexpected error during send: {e}", "error")
            self.disconnect_client()

    def _verify_server_callback(self, conn, cert, errnum, depth, preverify_ok):
        """
        Callback function for server certificate verification.
        Logs details about the server certificate and verification status.
        """
        if cert:
            subject = cert.get_subject()
            issuer = cert.get_issuer()
            self.log_message(f"Verifying server cert: Subject={subject.CN}, Issuer={issuer.CN}, Depth={depth}", "info")
        else:
            self.log_message(f"Verifying server cert: No cert presented at depth {depth}", "info")

        if not preverify_ok:
            self.log_message(f"Server cert verification failed: {SSL.Error(errnum).args[0]}", "error")
            return False # Reject connection if verification fails

        self.log_message(f"Server cert pre-verification OK: {preverify_ok}", "info")
        return preverify_ok

    def on_closing(self):
        """Handles the window closing event to ensure client is disconnected."""
        if self.client_connected:
            self.disconnect_client()
        self.master.destroy()

if __name__ == "__main__":
    # To run this code, you'll need client-cert.pem, client-cert.key, and ca-cert.pem
    # if the server requires client authentication and you want to verify the server.
    # See the previous server example for how to generate these using OpenSSL.

    # Example OpenSSL commands to generate client cert/key (signed by your CA):
    # 1. Generate client private key and certificate signing request (CSR)
    # openssl genrsa -out client-cert.key 2048
    # openssl req -new -key client-cert.key -out client-cert.csr -subj "/CN=MyClient"

    # 2. Sign the client CSR with your CA (assuming ca-cert.pem and ca-cert.key exist)
    # openssl x509 -req -in client-cert.csr -CA ca-cert.pem -CAkey ca-cert.key -CAcreateserial -out client-cert.pem -days 365 -sha256

    root = tk.Tk()
    app = TLSClientApp(root)
    root.mainloop()
