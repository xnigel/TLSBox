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
import time # Added for time.sleep in handshake retry logic
import base64
import tempfile

# === Paste your Base64 encoded PNG string here ===
# This is a placeholder. You should replace this with the actual Base64 string of your icon.
# Example (this is a tiny red square for demonstration, your actual string will be much longer):
ICON_PNG_BASE64 = """
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
"""

class TLSClientApp:
    def __init__(self, master):
        self.master = master
        Client_ver = "01.00.00" # Updated version for robust data handling
        Client_yr = "2025.07.29"
        master.title("TLS Client" + " (v" + Client_ver +")" + " - " + Client_yr + " - nigel.zhai@ul.com")
        master.geometry("500x650")
        master.minsize(500, 700) # Set minimum window size
        master.maxsize(500, 700)
        master.resizable(True, True) # Allow resizing

        # Set the window icon
        self.set_window_icon()

        self.client_connected = False
        self.ssl_conn = None
        self.client_socket = None
        self.client_thread = None

        # --- Configuration Frame ---
        config_frame = ttk.LabelFrame(master, text="Client Configuration", padding="5")
        config_frame.pack(padx=5, pady=10, fill="x", expand=False)

        # Connection details
        self.ip_var = tk.StringVar(value="192.168.1.104")
        self.port_var = tk.StringVar(value="8080")

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
        ttk.Label(config_frame, text="Client Private Key:").grid(row=row, column=0, sticky="w", pady=2)
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

        self.disconnect_button = ttk.Button(button_frame, text="Disconnect", command=self.disconnect_client, state="disabled", style="Red.TButton")
        self.disconnect_button.pack(side="right", padx=5)

        self.connect_button = ttk.Button(button_frame, text="Connect", command=self.connect_client, style="Green.TButton")
        self.connect_button.pack(side="right", padx=5)

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

    def set_window_icon(self):
        try:
            # Decode the Base64 string
            icon_data = base64.b64decode(ICON_PNG_BASE64)

            # Attempt to use PhotoImage directly
            try:
                photo_image = tk.PhotoImage(data=icon_data)
                self.master.iconphoto(True, photo_image)
            except tk.TclError:
                # Fallback to .ico if PhotoImage fails (e.g., if the data isn't a valid PNG or Tkinter version issues)
                # This requires writing to a temporary .ico file.
                print("PhotoImage failed, attempting .ico fallback...")
                temp_ico_path = os.path.join(tempfile.gettempdir(), "temp_icon.ico")
                with open(temp_ico_path, "wb") as f:
                    f.write(icon_data) # Assuming the base64 could also be an ICO
                self.master.iconbitmap(temp_ico_path)
                os.remove(temp_ico_path) # Clean up the temporary file

        except Exception as e:
            print(f"Error setting PNG icon from Base64 or ICO fallback: {e}")
            print("Ensure the Base64 string is correct and represents a valid PNG or ICO image.")
            # Fallback to a default Tkinter icon if all else fails
            self.master.iconbitmap(default="::tk::icons::question")


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
                # Attempt graceful SSL shutdown
                self.ssl_conn.shutdown() 
                self.ssl_conn.close()
            except SSL.Error as e:
                # Log SSL shutdown errors
                error_details = []
                if e.args and isinstance(e.args[0], (list, tuple)) and all(isinstance(item, tuple) and len(item) == 4 for item in e.args[0]):
                    for err_code, lib, func, reason in e.args[0]:
                        error_details.append(f"  - Library: {lib}, Function: {func}, Reason: {reason}")
                    self.log_message(f"Error during SSL connection shutdown: {e}\nDetails:\n" + "\n".join(error_details), "error")
                else:
                    self.log_message(f"Error during SSL connection shutdown: {e} (No detailed OpenSSL error stack available)", "error")
            except OSError as e:
                self.log_message(f"Error closing client socket during shutdown: {e}", "error")
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
            # SSL.TLS_CLIENT_METHOD allows negotiation of TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3
            context = SSL.Context(SSL.TLS_CLIENT_METHOD)

            # Set TLS protocol options based on user selection
            options = 0 
            if tls_version == "TLSv1.0":
                options |= SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1_1 | SSL.OP_NO_TLSv1_2 | SSL.OP_NO_TLSv1_3 # Allow only TLSv1.0
            elif tls_version == "TLSv1.1":
                options |= SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_2 | SSL.OP_NO_TLSv1_3 # Allow only TLSv1.1
            elif tls_version == "TLSv1.2":
                options |= SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1 | SSL.OP_NO_TLSv1_3 # Allow only TLSv1.2
            elif tls_version == "TLSv1.3":
                options |= SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1 | SSL.OP_NO_TLSv1_2 # Allow only TLSv1.3
            context.set_options(options)
            self.log_message(f"SSL Context created with selected TLS version: {tls_version}", "info")

            # Load client certificate and private key if provided (for client authentication)
            if cert_file and key_file:
                try:
                    context.use_certificate_file(cert_file)
                    context.use_privatekey_file(key_file)
                    self.log_message(f"Client Certificate loaded: {cert_file}", "info")
                except SSL.Error as e:
                    self.log_message(f"Error loading client certificate/key: {e}", "error")
                    raise # Re-raise to be caught by outer exception handler
            else:
                self.log_message("No client certificate provided. Client authentication will not be attempted.", "warning")

            # Load CA certificate for server certificate verification
            if ca_file:
                try:
                    context.load_verify_locations(ca_file)
                    context.set_verify(SSL.VERIFY_PEER, self._verify_server_callback)
                    self.log_message(f"CA Certificate loaded for server verification: {ca_file}", "info")
                except SSL.Error as e:
                    self.log_message(f"Error loading CA certificate: {e}", "error")
                    raise # Re-raise
            else:
                context.set_verify(SSL.VERIFY_NONE, self._verify_server_callback)
                self.log_message("No CA Certificate provided. Server certificate will not be verified.", "warning")

            # Create a standard socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5) # Set a timeout for connection attempts

            # Connect to the server
            self.client_socket.connect((ip_address, port))
            self.log_message(f"Connected to {ip_address}:{port}", "success")

            # Wrap the socket with SSL
            self.ssl_conn = SSL.Connection(context, self.client_socket)
            self.ssl_conn.set_connect_state()

            # Perform the SSL handshake
            # Loop until handshake is successful or a fatal error occurs
            while True:
                try:
                    self.ssl_conn.do_handshake()
                    break # Handshake successful, exit loop
                except SSL.WantReadError:
                    # Handshake needs more data, wait and retry
                    self.log_message("Handshake: Waiting for more data...", "info")
                    # It's good practice to wait a bit to avoid busy-waiting
                    time.sleep(0.1) 
                    continue # Try handshake again
                except SSL.Error as e:
                    # Other SSL errors are fatal
                    error_details = []
                    # Check if e.args[0] is iterable and contains error details
                    if e.args and isinstance(e.args[0], (list, tuple)) and all(isinstance(item, tuple) and len(item) == 4 for item in e.args[0]):
                        for err_code, lib, func, reason in e.args[0]:
                            error_details.append(f"  - Library: {lib}, Function: {func}, Reason: {reason}")
                        self.log_message(f"SSL Handshake Error: {e}\nDetails:\n" + "\n".join(error_details), "error")
                    else:
                        self.log_message(f"SSL Handshake Error: {e} (No detailed OpenSSL error stack available)", "error")
                    self.disconnect_client()
                    return # Exit thread on fatal error
                except Exception as e:
                    self.log_message(f"Unexpected error during handshake: {e}", "error")
                    self.disconnect_client()
                    return # Exit thread on unexpected error

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
            self.log_message(f"Connection timed out to {ip_address}:{port}", "error")
            self.disconnect_client()
        except socket.error as e:
            self.log_message(f"Socket Error: {e}", "error")
            self.disconnect_client()
        except SSL.Error as e:
            # This block now handles other SSL.Error types after WantReadError is handled in the loop
            error_details = []
            if e.args and isinstance(e.args[0], (list, tuple)) and all(isinstance(item, tuple) and len(item) == 4 for item in e.args[0]):
                for err_code, lib, func, reason in e.args[0]:
                    error_details.append(f"  - Library: {lib}, Function: {func}, Reason: {reason}")
                self.log_message(f"SSL Handshake Error: {e}\nDetails:\n" + "\n".join(error_details), "error")
            else:
                self.log_message(f"SSL Handshake Error: {e} (No detailed OpenSSL error stack available)", "error")
            self.disconnect_client()
        except Exception as e:
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
                # Use a smaller buffer for recv in a polling loop to be more responsive
                data = self.ssl_conn.recv(4096) 
                if not data:
                    # A clean SSL shutdown by the peer results in recv returning 0 bytes
                    self.log_message("Server initiated clean SSL shutdown or closed the connection.", "info")
                    self.disconnect_client()
                    break # Exit loop if client disconnected
                self.log_message(f"Received: {data.decode('utf-8', errors='ignore')}", "received")
            except SSL.WantReadError:
                # No data available, continue loop. This is expected in a non-blocking loop.
                time.sleep(0.05) # Small delay to prevent busy-waiting
                continue
            except SSL.ZeroReturnError:
                # This explicitly handles a clean SSL shutdown from the peer
                self.log_message("Server initiated clean SSL shutdown (ZeroReturnError).", "info")
                self.disconnect_client()
                break
            except SSL.Error as e:
                # Log SSL errors during receive
                error_details = []
                if e.args and isinstance(e.args[0], (list, tuple)) and all(isinstance(item, tuple) and len(item) == 4 for item in e.args[0]):
                    for err_code, lib, func, reason in e.args[0]:
                        error_details.append(f"  - Library: {lib}, Function: {func}, Reason: {reason}")
                    self.log_message(f"SSL receive error: {e}\nDetails:\n" + "\n".join(error_details), "error")
                else:
                    self.log_message(f"SSL receive error: {e} (No detailed OpenSSL error stack available)", "error")
                self.disconnect_client()
                break
            except socket.error as e:
                # Log socket errors during receive
                if e.errno == 10035: # WSAEWOULDBLOCK
                    time.sleep(0.05) # Small delay to prevent busy-waiting
                    continue
                elif e.errno == 10054: # WSAECONNRESET
                    self.log_message(f"Socket receive error (Connection Reset by Peer): {e}", "error")
                else:
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

        message_bytes = message.encode('utf-8')
        try:
            # Loop send to handle SSL.WantWriteError
            while True:
                try:
                    self.ssl_conn.sendall(message_bytes)
                    break # Send successful, exit loop
                except SSL.WantWriteError:
                    self.log_message("Send: Waiting for write buffer to clear...", "info")
                    time.sleep(0.05) # Small delay to prevent busy-waiting
                    continue
        except SSL.Error as e:
            error_details = []
            if e.args and isinstance(e.args[0], (list, tuple)) and all(isinstance(item, tuple) and len(item) == 4 for item in e.args[0]):
                for err_code, lib, func, reason in e.args[0]:
                    error_details.append(f"  - Library: {lib}, Function: {func}, Reason: {reason}")
                self.log_message(f"SSL send error: {e}\nDetails:\n" + "\n".join(error_details), "error")
            else:
                self.log_message(f"SSL send error: {e} (No detailed OpenSSL error stack available)", "error")
            self.disconnect_client()
        except socket.error as e:
            self.log_message(f"Socket send error: {e}", "error")
            self.disconnect_client()
        except Exception as e:
            self.log_message(f"Unexpected error during send: {e}", "error")
            self.disconnect_client()
        else: # This block executes if no exceptions occurred in the try block
            self.log_message(f"Sent: {message}", "sent")
            self.message_entry.delete(0, tk.END) # Clear the input field

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
            # Log the specific OpenSSL error reason
            error_reason = SSL.Error(errnum).args[0] if errnum else "Unknown error"
            self.log_message(f"Server cert verification failed: {error_reason}", "error")
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
