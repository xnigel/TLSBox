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
from tkinter import scrolledtext, messagebox, simpledialog, filedialog
import socket
import threading
import queue
import binascii
import time
import sys

# Define a thread-safe queue for packets to be displayed in the GUI
packet_display_queue = queue.Queue()
# Define a dictionary to hold packets that are paused for modification
# Key: (connection_id, packet_direction, packet_index_in_stream)
# Value: {'data': bytes, 'event': threading.Event}
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
        TLSproxy_ver = "00.03.00"
        TLSproxy_yr = "2025.07.28"
        master.title("TLSproxy" + " (v" + TLSproxy_ver +")" + " - " + TLSproxy_yr + " - nigel.zhai@ul.com")
        master.title("TLS Sniffer (TCP Proxy)")
        master.geometry("580x700") # Set initial window size
        master.minsize(580, 660) # Set minimum window size
        master.maxsize(580, 900)
        master.protocol("WM_DELETE_WINDOW", self.on_closing) # Handle window close event

        self.running = False
        self.proxy_thread = None
        self.listen_socket = None

        # Variable for the "Hold Packets" toggle switch - MOVED HERE
        self.hold_packets_var = tk.BooleanVar(value=False) # Default to automatic forwarding

        self.create_widgets()
        self.update_gui_thread = threading.Thread(target=self.update_gui, daemon=True)
        self.update_gui_thread.start()

        # Dictionary to store packet details for the listbox
        # Key: Listbox index, Value: {'conn_id': int, 'direction': str, 'stream_index': int, 'raw_data': bytes}
        self.packet_details = {}
        self.current_packet_index = 0 # Unique index for packets in the listbox

    def create_widgets(self):
        # Configuration Frame
        config_frame = tk.LabelFrame(self.master, text="Configuration", padx=2, pady=5)
        config_frame.pack(pady=5, padx=2, fill="x")

        # Listen IP and Port
        tk.Label(config_frame, text="Listen IP:").grid(row=0, column=0, padx=2, pady=5, sticky="w")
        self.listen_ip_entry = tk.Entry(config_frame, width=14)
        self.listen_ip_entry.insert(0, "0.0.0.0") # Default to listen on all interfaces
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
            text="Hold Packets\n(Manual Forwarding)",
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

        self.export_button = tk.Button(control_frame, text="Export Packets", command=self.export_packets, width=button_width, height=button_height)
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
                    held_packets[key]['event'].set()
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
            messagebox.showinfo("Info", "Proxy is not running.")
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
        #messagebox.showinfo("Info", "Proxy stopped.")

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

                # Add packet to display queue
                packet_display_queue.put({
                    'conn_id': conn_id,
                    'direction': direction,
                    'size': len(data),
                    'timestamp': time.time(),
                    'raw_data': data,
                    'stream_index': stream_index # Unique index within this stream direction
                })

                # Prepare for holding if manual forwarding is enabled
                packet_key = (conn_id, direction, stream_index)
                stream_index += 1 # Increment for next packet in this stream

                if self.hold_packets_var.get(): # Check the state of the toggle switch
                    # Create an event for this packet, initially not set (meaning it's held)
                    packet_event = threading.Event()
                    with held_packets_lock:
                        held_packets[packet_key] = {'data': data, 'event': packet_event}
                    # Wait for the event to be set (i.e., packet is forwarded)
                    packet_event.wait() # This will block until forward_packet is called for this key
                else:
                    # If not holding, the packet isn't added to held_packets, and is sent immediately.
                    # We still need to initialize packet_event and set it immediately to not block.
                    # This path is for "automatic" forwarding.
                    pass # Data will be sent below

                # Retrieve potentially modified data (or original data if not held/modified)
                data_to_send = data # Default to original data
                if self.hold_packets_var.get():
                    with held_packets_lock:
                        # Ensure the packet is still in held_packets before trying to pop
                        if packet_key in held_packets:
                            data_to_send = held_packets.pop(packet_key)['data'] # Get data and remove from held_packets
                        else:
                            # This case should ideally not happen if packet_event.wait() unblocked,
                            # but as a safeguard, if somehow it's missing, send the original data.
                            print(f"Warning: Packet {packet_key} unexpectedly not in held_packets after wait.")

                destination_socket.sendall(data_to_send)

            except socket.timeout:
                continue # No data, try again
            except OSError as e:
                # Connection reset by peer, broken pipe, etc.
                print(f"Connection {conn_id} ({direction}): Socket error: {e}")
                break
            except Exception as e:
                print(f"Connection {conn_id} ({direction}): Unexpected error during forwarding: {e}")
                break

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

                display_text = (
                    f"[{self.current_packet_index:04d}] "
                    f"ConnID:{conn_id} | {direction} | Size:{size} bytes | Time:{timestamp:.2f}"
                )
                self.packet_listbox.insert(tk.END, display_text)
                self.packet_listbox.see(tk.END) # Scroll to the end

                # Store full packet details for later retrieval
                self.packet_details[self.current_packet_index] = {
                    'conn_id': conn_id,
                    'direction': direction,
                    'stream_index': stream_index,
                    'raw_data': raw_data
                }
                self.current_packet_index += 1

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
            if self.hold_packets_var.get():
                self.forward_button.config(state=tk.NORMAL)
            else:
                self.forward_button.config(state=tk.DISABLED)
        else:
            self.modify_button.config(state=tk.DISABLED)
            self.forward_button.config(state=tk.DISABLED)

        self.packet_detail_text.config(state=tk.DISABLED)

    def get_selected_packet_key(self):
        selected_indices = self.packet_listbox.curselection()
        if not selected_indices:
            return None
        listbox_index = selected_indices[0]
        packet_info = self.packet_details.get(listbox_index)
        if packet_info:
            return (packet_info['conn_id'], packet_info['direction'], packet_info['stream_index'])
        return None

    def modify_selected_packet(self):
        packet_key = self.get_selected_packet_key()
        if not packet_key:
            messagebox.showwarning("Warning", "No packet selected to modify.")
            return

        with held_packets_lock:
            if packet_key not in held_packets:
                messagebox.showwarning("Warning", "Selected packet is not currently held. It might have already been forwarded or not yet arrived, or 'Hold Packets' is not enabled.")
                return

            current_data = held_packets[packet_key]['data']
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
                    held_packets[packet_key]['data'] = new_data
                    messagebox.showinfo("Success", "Packet data modified. Remember to forward it.")
                    # Update the raw_data in self.packet_details for display refresh
                    self.packet_details[self.packet_listbox.curselection()[0]]['raw_data'] = new_data
                    self.display_packet_details() # Refresh display to show modified data
                except binascii.Error:
                    messagebox.showerror("Error", "Invalid hexadecimal input. Please enter only valid hex characters (0-9, a-f, A-F).")
                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred during modification: {e}")

    def forward_selected_packet(self):
        packet_key = self.get_selected_packet_key()
        if not packet_key:
            messagebox.showwarning("Warning", "No packet selected to forward.")
            return

        if not self.hold_packets_var.get():
            messagebox.showinfo("Info", "Automatic forwarding is enabled. Packets are sent immediately.")
            return

        with held_packets_lock:
            if packet_key in held_packets:
                # Set the event to release the packet
                held_packets[packet_key]['event'].set()
                # The messagebox "Packet forwarded." is removed as requested.
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
        messagebox.showinfo("Cleared", "All displayed and held packets cleared.")

    def export_packets(self):
        if not self.packet_details:
            messagebox.showinfo("Info", "No packets to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not file_path:
            return # User cancelled

        try:
            with open(file_path, 'w') as f:
                for listbox_index in sorted(self.packet_details.keys()):
                    packet_info = self.packet_details[listbox_index]
                    conn_id = packet_info['conn_id']
                    direction = packet_info['direction']
                    stream_index = packet_info['stream_index']
                    raw_bytes = packet_info['raw_data']

                    f.write(f"--- Packet [{listbox_index:04d}] ---\n")
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
                messagebox.showinfo("Success", f"Packets exported successfully to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export packets: {e}")


    def on_closing(self):
        self.stop_proxy()
        self.master.destroy()
        sys.exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = TLSSnifferApp(root)
    root.iconbitmap('logo.ico')
    root.mainloop()