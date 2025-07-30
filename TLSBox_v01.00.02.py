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
        TLSproxy_ver = "01.00.02" # Updated version number
        TLSproxy_yr = "2025.07.31" # Updated date
        master.title("TLSBox" + " (v" + TLSproxy_ver +")" + " - " + TLSproxy_yr + " - nigel.zhai@ul.com")
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
