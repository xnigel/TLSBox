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
#   05. v01.00.01 Fixed the Hold/modify/forward packets issue. 2025.07.30
#   06. v01.00.02 Click Modify button to display both original and modified packets. 2025.07.31
#   07. v01.01.00 Changed icon and logo
# _______________________________________________________________________________
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, filedialog
import socket
import threading
import queue
import binascii
import datetime
import time
import base64
import sys
import os
import tempfile

# === Paste your Base64 encoded PNG string here ===
# This is a placeholder. You should replace this with the actual Base64 string of your icon.
# Example (this is a tiny red square for demonstration, your actual string will be much longer):
ICON_PNG_BASE64 = """
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
"""

# Define a thread-safe queue for packets to be displayed in the GUI
packet_display_queue = queue.Queue()
# Define a dictionary to hold packets that are paused for modification
# Key: (connection_id, packet_direction, stream_index)
# Value: {'original_data': bytes, 'modified_data': bytes, 'event': threading.Event}
held_packets = {}
held_packets_lock = threading.Lock() # Lock for accessing held_packets dictionary

# Global counter for unique connection IDs
connection_id_counter = 0
connection_id_counter_lock = threading.Lock()

# Packet direction constants
CLIENT_TO_SERVER = "Client -> Server"
SERVER_TO_CLIENT = "Server -> Client"

class TLSSnifferApp:
    def __init__(self, master):
        self.master = master
        TLSproxy_ver = "01.01.00" # Updated version number
        TLSproxy_yr = "2025.08.04" # Updated date
        master.title("TLSBox" + " (v" + TLSproxy_ver +")" + " - " + TLSproxy_yr + " - Nigel Zhai")
        master.geometry("580x700") # Set initial window size
        master.minsize(580, 660) # Set minimum window size
        master.maxsize(580, 900)
        master.protocol("WM_DELETE_WINDOW", self.on_closing) # Handle window close event

        # Set the window icon
        self.set_window_icon()

        self.running = False
        self.proxy_thread = None
        self.listen_socket = None

        # Variable for the "Hold Packets" toggle switch
        self.hold_packets_var = tk.BooleanVar(value=False) # Default to automatic forwarding

        self.create_widgets()
        self.update_gui_thread = threading.Thread(target=self.update_gui, daemon=True)
        self.update_gui_thread.start()

        # Dictionary to store packet details for the listbox
        # Key: Listbox index, Value: {'conn_id': int, 'direction': str, 'stream_index': int, 'raw_data': bytes, 'type': 'original' or 'modified'}
        self.packet_details = {}
        self.current_packet_index = 0 # Unique index for packets in the listbox

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


    def create_widgets(self):
        # Configuration Frame
        config_frame = tk.LabelFrame(self.master, text="Configuration", padx=2, pady=5)
        config_frame.pack(pady=5, padx=2, fill="x")

        # Listen IP and Port
        tk.Label(config_frame, text="Listen IP:").grid(row=0, column=0, padx=2, pady=5, sticky="w")
        self.listen_ip_entry = tk.Entry(config_frame, width=14)
        self.listen_ip_entry.insert(0, "192.168.1.104") # Default to listen on all interfaces
        self.listen_ip_entry.grid(row=0, column=1, padx=2, pady=5, sticky="w")

        tk.Label(config_frame, text="Listen Port:").grid(row=1, column=0, padx=2, pady=5, sticky="w")
        self.listen_port_entry = tk.Entry(config_frame, width=14)
        self.listen_port_entry.insert(0, "8080") # Default port
        self.listen_port_entry.grid(row=1, column=1, padx=2, pady=5, sticky="w")

        # Target IP/Host and Port
        tk.Label(config_frame, text="Target IP/Host:").grid(row=0, column=2, padx=2, pady=5, sticky="w")
        self.target_ip_host_entry = tk.Entry(config_frame, width=14)
        self.target_ip_host_entry.insert(0, "192.168.1.104") # Default target
        self.target_ip_host_entry.grid(row=0, column=3, padx=2, pady=5, sticky="w")

        tk.Label(config_frame, text="Target Port:").grid(row=1, column=2, padx=2, pady=5, sticky="w")
        self.target_port_entry = tk.Entry(config_frame, width=14)
        self.target_port_entry.insert(0, "443") # Default target port (HTTPS)
        self.target_port_entry.grid(row=1, column=3, padx=2, pady=5, sticky="w")

        # Control Buttons and Status
        self.status_label = tk.Label(config_frame, text="Status: Stopped", fg="blue")
        self.status_label.grid(row=2, column=0, columnspan=6, padx=5, pady=5, sticky="w") # Spanning more columns

        self.start_button = tk.Button(config_frame, text="Start Proxy", command=self.start_proxy, bg='#D1FFBD', fg="black")
        self.start_button.grid(row=0, column=4, columnspan=2, padx=20, pady=5, sticky="w") # Moved to next row

        self.stop_button = tk.Button(config_frame, text="Stop Proxy", command=self.stop_proxy, state=tk.DISABLED, bg='#FF5C5C', fg="black")
        self.stop_button.grid(row=1, column=4, columnspan=2, padx=20, pady=5, sticky="e") # Moved to next row


        # ========================================================================================================
        # Packet List Frame (height adjusted)
        packet_list_frame = tk.LabelFrame(self.master, text="Captured Packets", padx=5, pady=5)
        packet_list_frame.pack(pady=5, padx=5, fill="both", expand=True)

        self.packet_listbox = tk.Listbox(packet_list_frame, width=80, height=6) # Adjusted height to 12
        self.packet_listbox.pack(side="left", fill="both", expand=True)
        self.packet_listbox.bind("<<ListboxSelect>>", self.display_packet_details)

        packet_list_scrollbar = tk.Scrollbar(packet_list_frame, command=self.packet_listbox.yview)
        packet_list_scrollbar.pack(side="right", fill="y")
        self.packet_listbox.config(yscrollcommand=packet_list_scrollbar.set)

        # ========================================================================================================
        # Packet Details Frame (height adjusted)
        packet_detail_frame = tk.LabelFrame(self.master, text="Packet Details (Hex & ASCII)", padx=5, pady=5)
        packet_detail_frame.pack(pady=5, padx=5, fill="both", expand=True)

        self.packet_detail_text = scrolledtext.ScrolledText(packet_detail_frame, wrap="word", width=80, height=12, state=tk.DISABLED) # Adjusted height to 12
        self.packet_detail_text.pack(fill="both", expand=True)

        # Control Frame
        control_frame = tk.Frame(self.master, padx=5, pady=5)
        control_frame.pack(pady=5, padx=5, fill="x")

        # "Hold Packets" toggle switch
        self.hold_packets_toggle = tk.Checkbutton(
            control_frame,
            text="Hold Packets\n(Forward Manually)",
            variable=self.hold_packets_var,
            command=self.toggle_hold_packets,
            anchor="w",  # Align text to the left
            justify="left"
        )
        self.hold_packets_toggle.pack(side="left", padx=5)

        # Button width for consistency
        button_width = 12
        button_height = 2

        self.modify_button = tk.Button(control_frame, text="Modify\nSelected Packet", command=self.modify_selected_packet, state=tk.DISABLED, width=button_width, height=button_height, anchor="w")
        self.modify_button.pack(side="left", padx=5, anchor="w")

        # Forward button state now depends on the toggle
        self.forward_button = tk.Button(control_frame, text="Forward\nSelected Packet", command=self.forward_selected_packet, state=tk.DISABLED, width=button_width, height=button_height, anchor="w")
        self.forward_button.pack(side="left", padx=5, anchor="w")

        self.clear_button = tk.Button(control_frame, text="Clear Packets", command=self.clear_packets, width=button_width, height=button_height)
        self.clear_button.pack(side="right", padx=5)

        self.export_button = tk.Button(control_frame, text="Export\nSelected Packets", command=self.export_packets, width=button_width, height=button_height, bg='#FFEFB3', fg="black")
        self.export_button.pack(side="right", padx=5)


    def toggle_hold_packets(self):
        # Update the state of the forward button based on the toggle
        if self.hold_packets_var.get():
            self.forward_button.config(state=tk.NORMAL)
        else:
            self.forward_button.config(state=tk.DISABLED)
            # If turning off manual hold, release any currently held packets
            with held_packets_lock:
                for key in list(held_packets.keys()):
                    held_packets[key]['event'].set() # Release the event to unblock the forwarding thread
                held_packets.clear()


    def start_proxy(self):
        if self.running:
            messagebox.showinfo("Info", "Proxy is already running.")
            return

        try:
            listen_ip = self.listen_ip_entry.get()
            listen_port = int(self.listen_port_entry.get())
            target_ip_host = self.target_ip_host_entry.get()
            target_port = int(self.target_port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter valid port numbers.")
            return

        if not listen_ip or not target_ip_host:
            messagebox.showerror("Error", "Please enter Listen IP and Target IP/Host.")
            return

        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text=f"Status: Listening on client [{listen_ip}:{listen_port}]. Targeting on server [{target_ip_host}:{target_port}]", fg="green")

        self.proxy_thread = threading.Thread(target=self._run_proxy_server, args=(listen_ip, listen_port, target_ip_host, target_port), daemon=True)
        self.proxy_thread.start()

    def stop_proxy(self):
        if not self.running:
            # messagebox.showinfo("Info", "Proxy is not running.")
            return

        self.running = False
        if self.listen_socket:
            try:
                self.listen_socket.shutdown(socket.SHUT_RDWR)
                self.listen_socket.close()
            except OSError as e:
                print(f"Error closing listen socket: {e}")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped", fg="blue")
        # messagebox.showinfo("Info", "Proxy stopped.")

    def _run_proxy_server(self, listen_ip, listen_port, target_ip_host, target_port):
        global connection_id_counter # Ensure we can modify the global counter
        try:
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.bind((listen_ip, listen_port)) # Use the specified listen_ip
            self.listen_socket.listen(5)
            print(f"Proxy listening on {listen_ip}:{listen_port}...")
            print(f"Forwarding to {target_ip_host}:{target_port}")

            while self.running:
                try:
                    client_socket, client_addr = self.listen_socket.accept()
                    with connection_id_counter_lock:
                        conn_id = connection_id_counter
                        connection_id_counter += 1
                    print(f"Accepted connection {conn_id} from {client_addr[0]}:{client_addr[1]}")
                    client_handler = threading.Thread(
                        target=self._handle_client_connection,
                        args=(client_socket, client_addr, target_ip_host, target_port, conn_id),
                        daemon=True
                    )
                    client_handler.start()
                except OSError as e:
                    if self.running: # Only print error if it's not due to intentional shutdown
                        print(f"Error accepting connection: {e}")
                    break # Exit loop if socket is closed or other critical error
                except Exception as e:
                    print(f"Unexpected error in proxy server loop: {e}")
                    break
        except OSError as e:
            self.master.after(0, lambda: messagebox.showerror("Error", f"Could not start proxy: {e}\n(Perhaps port {listen_port} is in use or requires elevated privileges)"))
            self.master.after(0, self.stop_proxy) # Stop the proxy if it failed to start
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Error", f"An unexpected error occurred: {e}"))
            self.master.after(0, self.stop_proxy)

    def _handle_client_connection(self, client_socket, client_addr, target_ip_host, target_port, conn_id):
        server_socket = None
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((target_ip_host, target_port)) # Use the target_ip_host
            print(f"Connection {conn_id}: Connected to target {target_ip_host}:{target_port}")

            # Create threads for bidirectional data forwarding
            client_to_server_thread = threading.Thread(
                target=self._forward_data,
                args=(client_socket, server_socket, CLIENT_TO_SERVER, conn_id),
                daemon=True
            )
            server_to_client_thread = threading.Thread(
                target=self._forward_data,
                args=(server_socket, client_socket, SERVER_TO_CLIENT, conn_id),
                daemon=True
            )

            client_to_server_thread.start()
            server_to_client_thread.start()

            client_to_server_thread.join() # Wait for both threads to finish
            server_to_client_thread.join()

        except Exception as e:
            print(f"Connection {conn_id}: Error handling connection: {e}")
        finally:
            if client_socket:
                client_socket.close()
            if server_socket:
                server_socket.close()
            print(f"Connection {conn_id}: Closed.")

    def _forward_data(self, source_socket, destination_socket, direction, conn_id):
        stream_index = 0
        while self.running:
            try:
                data = source_socket.recv(4096) # Read up to 4KB of data
                if not data:
                    break # Connection closed by source

                # Always add the original packet to the display queue and packet_details
                # This ensures all captured packets are logged, even if not held/modified
                self.master.after(0, lambda d=data, di=direction, ci=conn_id, si=stream_index:
                                  self._add_packet_to_display(d, di, ci, si, 'original'))

                data_to_send = data # Default to original data

                if self.hold_packets_var.get(): # Check the state of the toggle switch
                    # Prepare for holding if manual forwarding is enabled
                    packet_key = (conn_id, direction, stream_index)
                    
                    # Create an event for this packet, initially not set (meaning it's held)
                    packet_event = threading.Event()
                    with held_packets_lock:
                        held_packets[packet_key] = {
                            'original_data': data,
                            'modified_data': data, # Initially, modified data is the same as original
                            'event': packet_event
                        }
                    # Wait for the event to be set (i.e., packet is forwarded)
                    packet_event.wait() # This will block until forward_packet is called for this key

                    with held_packets_lock:
                        # Ensure the packet is still in held_packets before trying to pop
                        if packet_key in held_packets:
                            data_to_send = held_packets[packet_key]['modified_data'] # Get the (potentially modified) data
                            
                            # If modified_data is different from original_data, add the modified packet to display
                            if held_packets[packet_key]['original_data'] != data_to_send:
                                self.master.after(0, lambda d=data_to_send, di=direction, ci=conn_id, si=stream_index:
                                                  self._add_packet_to_display(d, di, ci, si, 'modified'))
                            
                            held_packets.pop(packet_key) # Remove from held_packets after forwarding
                        else:
                            # This case should ideally not happen if packet_event.wait() unblocked,
                            # but as a safeguard, if somehow it's missing, send the original data.
                            print(f"Warning: Packet {packet_key} unexpectedly not in held_packets after wait.")
                
                destination_socket.sendall(data_to_send)
                stream_index += 1 # Increment for next packet in this stream, regardless of holding

            except socket.timeout:
                continue # No data, try again
            except OSError as e:
                # Connection reset by peer, broken pipe, etc.
                print(f"Connection {conn_id} ({direction}): Socket error: {e}")
                break
            except Exception as e:
                print(f"Connection {conn_id} ({direction}): Unexpected error during forwarding: {e}")
                break

    def _add_packet_to_display(self, raw_data, direction, conn_id, stream_index, packet_type):
        """Helper function to add packet details to the GUI and internal storage."""
        display_text_prefix = ""
        if packet_type == 'original':
            display_text_prefix = "[ORIGINAL] "
        elif packet_type == 'modified':
            display_text_prefix = "[MODIFIED] "

        display_text = (
            f"[{self.current_packet_index:06d}] {display_text_prefix}"
            f"ConnID:{conn_id} | {direction} | Size:{len(raw_data)} bytes | Time:{time.strftime('%Y.%m.%d-%H:%M:%S')}"
        )
        self.packet_listbox.insert(tk.END, display_text)
        self.packet_listbox.see(tk.END) # Scroll to the end

        # Store full packet details for later retrieval
        self.packet_details[self.current_packet_index] = {
            'conn_id': conn_id,
            'direction': direction,
            'stream_index': stream_index,
            'raw_data': raw_data,
            'type': packet_type # Store the type of packet (original/modified)
        }
        self.current_packet_index += 1


    def update_gui(self):
        while True:
            try:
                packet_info = packet_display_queue.get(timeout=0.1) # Non-blocking get
                conn_id = packet_info['conn_id']
                direction = packet_info['direction']
                size = packet_info['size']
                timestamp = packet_info['timestamp']
                raw_data = packet_info['raw_data']
                stream_index = packet_info['stream_index']
                packet_type = packet_info.get('type', 'original') # Default to 'original' if not specified

                # Call the helper function to add the packet to display and storage
                self._add_packet_to_display(raw_data, direction, conn_id, stream_index, packet_type)

            except queue.Empty:
                pass # No new packets, continue checking
            except Exception as e:
                print(f"Error updating GUI: {e}")
            time.sleep(0.05) # Small delay to prevent busy-waiting

    def display_packet_details(self, event=None):
        selected_indices = self.packet_listbox.curselection()
        if not selected_indices:
            self.packet_detail_text.config(state=tk.NORMAL)
            self.packet_detail_text.delete(1.0, tk.END)
            self.packet_detail_text.config(state=tk.DISABLED)
            # Disable buttons if no packet is selected
            self.modify_button.config(state=tk.DISABLED)
            self.forward_button.config(state=tk.DISABLED)
            return

        listbox_index = selected_indices[0]
        packet_data = self.packet_details.get(listbox_index)

        self.packet_detail_text.config(state=tk.NORMAL)
        self.packet_detail_text.delete(1.0, tk.END)

        if packet_data:
            raw_bytes = packet_data['raw_data']
            hex_dump = binascii.hexlify(raw_bytes).decode('ascii')
            ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes])

            formatted_output = ""
            for i in range(0, len(hex_dump), 32): # 16 bytes per line (32 hex chars)
                hex_part = hex_dump[i:i+32]
                ascii_part = ascii_dump[i//2 : i//2 + 16]
                formatted_output += f"{hex_part:<32}  {ascii_part}\n"

            self.packet_detail_text.insert(tk.END, formatted_output)
            # Enable modify button when a packet is selected
            self.modify_button.config(state=tk.NORMAL)
            # Enable forward button only if "Hold Packets" toggle is active
            # and the selected packet is an 'original' type that is currently held
            if self.hold_packets_var.get():
                packet_key = (packet_data['conn_id'], packet_data['direction'], packet_data['stream_index'])
                with held_packets_lock:
                    if packet_key in held_packets and packet_data['type'] == 'original':
                        self.forward_button.config(state=tk.NORMAL)
                    else:
                        self.forward_button.config(state=tk.DISABLED)
            else:
                self.forward_button.config(state=tk.DISABLED)
        else:
            self.modify_button.config(state=tk.DISABLED)
            self.forward_button.config(state=tk.DISABLED)

        self.packet_detail_text.config(state=tk.DISABLED)

    def get_selected_packet_key(self):
        selected_indices = self.packet_listbox.curselection()
        if not selected_indices:
            return None, None # Return None for key and listbox_index
        listbox_index = selected_indices[0]
        packet_info = self.packet_details.get(listbox_index)
        if packet_info and packet_info['type'] == 'original': # Only allow modifying original packets
            return (packet_info['conn_id'], packet_info['direction'], packet_info['stream_index']), listbox_index
        return None, None

    def modify_selected_packet(self):
        packet_key, listbox_index = self.get_selected_packet_key()
        if not packet_key:
            messagebox.showwarning("Warning", "No original packet selected to modify, or selected packet is already a modified version.")
            return

        with held_packets_lock:
            if packet_key not in held_packets:
                messagebox.showwarning("Warning", "Selected packet is not currently held. It might have already been forwarded or 'Hold Packets' is not enabled.")
                return

            current_data = held_packets[packet_key]['modified_data'] # Get the current (possibly already modified) data
            current_hex = binascii.hexlify(current_data).decode('ascii')

            modified_hex = simpledialog.askstring(
                "Modify Packet Data",
                "Enter new packet data in hexadecimal (e.g., 48656C6C6F):\n"
                "(Warning: Incorrect hex may break the connection!)",
                initialvalue=current_hex,
                parent=self.master
            )

            if modified_hex is not None:
                try:
                    new_data = binascii.unhexlify(modified_hex)
                    held_packets[packet_key]['modified_data'] = new_data # Update the modified data in held_packets
                    messagebox.showinfo("Success", "Packet data modified. Remember to forward it.")
                    
                    # No need to refresh display immediately here, as the modified packet will be displayed
                    # when it's actually forwarded.
                    # The original packet in self.packet_details should remain as the original.
                    
                except binascii.Error:
                    messagebox.showerror("Error", "Invalid hexadecimal input. Please enter only valid hex characters (0-9, a-f, A-F).")
                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred during modification: {e}")

    def forward_selected_packet(self):
        packet_key, listbox_index = self.get_selected_packet_key()
        if not packet_key:
            messagebox.showwarning("Warning", "No original packet selected to forward.")
            return

        if not self.hold_packets_var.get():
            messagebox.showinfo("Info", "Automatic forwarding is enabled. Packets are sent immediately.")
            return

        with held_packets_lock:
            if packet_key in held_packets:
                # Set the event to release the packet
                held_packets[packet_key]['event'].set()
                # The _forward_data function will now handle adding the modified packet to display
                # if it was indeed modified.
            else:
                messagebox.showwarning("Warning", "Selected packet is not currently held or has already been forwarded.")


    def clear_packets(self):
        self.packet_listbox.delete(0, tk.END)
        self.packet_detail_text.config(state=tk.NORMAL)
        self.packet_detail_text.delete(1.0, tk.END)
        self.packet_detail_text.config(state=tk.DISABLED)
        self.packet_details.clear()
        self.current_packet_index = 0
        self.modify_button.config(state=tk.DISABLED)
        # Ensure forward button state reflects the toggle
        if self.hold_packets_var.get():
            self.forward_button.config(state=tk.NORMAL)
        else:
            self.forward_button.config(state=tk.DISABLED)

        with held_packets_lock:
            for key in list(held_packets.keys()):
                held_packets[key]['event'].set() # Release any held packets
            held_packets.clear()
        # messagebox.showinfo("Cleared", "All displayed and held packets cleared.")

    def export_packets(self):
        if not self.packet_details:
            messagebox.showinfo("Info", "No packets to export.")
            return

        now = datetime.datetime.now()
        current_datetime_str = now.strftime("%Y%m%d_%H%M%S") # Format: YYYYMMDD_HHMMSS

        file_path = filedialog.asksaveasfilename(
            defaultextension=".log", # Corrected: only the extension here
            initialfile=f"TLS_log_{current_datetime_str}.log", # Added initialfile
            filetypes=[("Log Files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not file_path:
            return # User cancelled

        try:
            with open(file_path, 'w') as f: # Open the file here
                f.write(f"===========================================================\n")
                f.write(f"TLS Sniffer Export - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Exported {len(self.packet_details)} packets:\n")
                f.write(f"Listen IP/Port: [{self.listen_ip_entry.get()} : {self.listen_port_entry.get()}]\n")
                f.write(f"Target IP/Port: [{self.target_ip_host_entry.get()} : {self.target_port_entry.get()}]\n")
                f.write(f"===========================================================\n\n\n")

                for listbox_index in sorted(self.packet_details.keys()):
                    packet_info = self.packet_details[listbox_index]
                    conn_id = packet_info['conn_id']
                    direction = packet_info['direction']
                    stream_index = packet_info['stream_index']
                    raw_bytes = packet_info['raw_data']
                    packet_type = packet_info.get('type', 'original') # Get packet type

                    f.write(f"--- Packet [{listbox_index:06d}] ({packet_type.upper()}) ---------------------------------------\n")
                    f.write(f"Connection ID: {conn_id}\n")
                    f.write(f"Direction: {direction}\n")
                    f.write(f"Stream Index: {stream_index}\n")
                    f.write(f"Size: {len(raw_bytes)} bytes\n\n")

                    # Hex Dump
                    f.write("Hexadecimal:\n")
                    hex_dump = binascii.hexlify(raw_bytes).decode('ascii')
                    for i in range(0, len(hex_dump), 32): # 16 bytes per line (32 hex chars)
                        hex_part = hex_dump[i:i+32]
                        f.write(f"{hex_part}\n")
                    f.write("\n")

                    # ASCII Dump
                    f.write("ASCII:\n")
                    ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes])
                    for i in range(0, len(ascii_dump), 16): # 16 chars per line
                        ascii_part = ascii_dump[i:i+16]
                        f.write(f"{ascii_part}\n")
                    f.write("\n")
            messagebox.showinfo("Success", f"Packets exported successfully to {file_path}") # This line should be outside the `with` block to ensure `f` is closed before showing info.
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export packets: {e}")


    def on_closing(self):
        self.stop_proxy()
        self.master.destroy()
        sys.exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = TLSSnifferApp(root)
    # root.iconbitmap('logo.ico')
    root.mainloop()
