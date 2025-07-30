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
iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAABhGlDQ1BJQ0MgcHJvZmlsZQAAKJF9kT1Iw0AcxV9TpSIVBwuKOGSogmIXFXEsVSyChdJWaNXB5NIvaNKQpLg4Cq4FBz8Wqw4uzro6uAqC4AeIu+Ck6CIl/i8ptIjx4Lgf7+497t4BQqPCVLMrCqiaZaTiMTGbWxUDrwhgEEGMY0Jipp5IL2bgOb7u4ePrXYRneZ/7c/QpeZMBPpE4ynTDIt4gnt20dM77xCFWkhTic+JJgy5I/Mh12eU3zkWHBZ4ZMjKpeeIQsVjsYLmDWclQiWeIw4qqUb6QdVnhvMVZrdRY6578hcG8tpLmOs0RxLGEBJIQIaOGMiqwEKFVI8VEivZjHv5hx58kl0yuMhg5FlCFCsnxg//B727NwvSUmxSMAd0vtv0xCgR2gWbdtr+Pbbt5AvifgSut7a82gLlP0uttLXwE9G8DF9dtTd4DLneAoSddMiRH8tMUCgXg/Yy+KQcM3AK9a25vrX2cPgAZ6mr5Bjg4BMaKlL3u8e6ezt7+PdPq7wf4kHLcgQVqtQAAAAZiS0dEAP8A/wD/oL2nkwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAAd0SU1FB+kHFwwqEPm3dvQAAAy5SURBVHja3Vt7cFTlFf+d7+5udje7m/dzNxgiYhRMabLJOJJiElJECiNYwEctpVaptY7tOJ12alvaOmPHMk7HP+jIVGUYxmotPqjYKBpCdORRXZNIeVUQQgib95Ls+3HvPf0jNGWzd5NAHoBnZv/Yvfd+e8/vO4/fOd/3ETMTplGaiXQhy4J0PUv5kFSHYKkQpOaCyQKCEQCYERUEP1TuB1GnqqA7Brh9wZBnDR+JTuf70XQAsIucZrMZpULHt6pAFQFlABUSYGPAQERC80FmlQEZIC/A3cw4SmAXMe1X/Dhczy7vVQ1AU5qzhIFlAqhn4FYAuUSTH57Bg8RoYaARstJQF2g9dFUB0JhauUBIvJoIKwGUItkMT4GozB0E7FRU5c1v+lo/uqIANJnKZ8Eg1gF4gIjmYiaF2c3A34Qsv1wTaGubcQCa0yrvZfBDIKq7rH8WBBLDhsIqA6p6mThwG4FfJO/A1hpuD087AB+YywslAz1OLB4BwTaRZySbBUZ7HozFdpiKC5GSnwN9dgYkixkgghoMIzZwHtFeD0Jn3Aid7kTkbBdi570A80RAkBnYBkXdvNjfcmjaAGi2VdzKoJ9C0Nrx7tWlW2GrvAXpC8uRVlUG0/VF0KfbIFIMY/t4LAbFG0Coww2v6wiG9rdi8EAbot19EwGimRjP1npdDVMOwJ40Zz2BniRCzVj3GYsKkL2iFtlLq2GrmA8p1TS5oBeNIXD0JPp3f4z+hg/h//w/44FwHIxn6ryu7VMGQLOtYrkK2kiCnMnu0WemIe/eZci7ewmsFfMwFelvtIROd6Ln9d3ofu1dhE6eGQuFDmb1d3Xelm2TBmCPxVlPAn8YS/mspdUoWLcS2XcumhbFR8vQJ4fQtf0f6HplF6ByUhDA2Fg7jiWMCcBem7OKiZ5JZvZk0KPoR/fCvuEeGO15M5oFlXAE7q1v4OzzryJytlsbA5VPMuPni32unZcMwEepznxZwnOUJOCl2PMw6yfrYH94zYzMejLp3bkHZze/DK/rcLKY8LGA+kTNUItLMxsnRVjC48mUN84qwOwnfwjHhrVXVHkAyF25GCUbH0X6wnLtGSaqViAef5du0EzZOk3TTytfyyQepSQzX/yLh1HwnRUX0pYM2etPzP1mIyST8f+ABkNQQpHE4JluBUnSpEDIWFQJEOH001swdPDzRBCAB1KstkMAnh3XBRpNzlnCgK2kwfBIr8Ocp38Kx4Z7Rn7r27UX7ZteHGZzF4n9odWwf//uke+dL+yAe9tb8ePpJJT86hFkLVk4JdbQ3/ARTv76OYROndXyhS+g4sFan2v/mBYgDFhHSeit40f3wf5wvFfIPj/8R04kRONYnyfue7R3AIEjJ0aZiQQlGJoyd8hetgiRrl6c+OWfwNHYaF+YC8Hr/0LOTzawS9aMAU2pXy8DcL9mqruj+qrw+fGkcP0qFF5kefFlNdbOtfLSpEGQJbGaiEoTAkVGGgrW3QWjIx9Xu5AkofB7K2Etv1krINqYsHoHzTMkANBoLCshopVag+bfcyey77wd14pYbp6D/Pu+BQihEQpoeVaqsToBAClFvxRAAmwpRfnIXX0HSBCuJcm7ewkybq9MtAJBmZBoWRwAO6jIyKB6rV5dzvJa2Crm4VoTfVY6cpbXaloBAfXvmsscIwBkmPNLCbgtwffTrMi6o/qqD3xJa5QlC5F6U4nWpVKjlFI1AoDQ8a0M5I6+y1Y5Hzbn/JnpcCkKYueHEj5KKHzZY6Y48pBZU6VFDw2qUKsBQPc7It0iW0WV1iynLyyHzmKeEQAGGg+g/Y8vgBUlPq19bxXsD3778jICEdKrK3DupTeghiOj3ICcjeS06aqtlTYitSyBylpTkVZVNnPVnS8A3+fHASW+Nxjt6Z9cRii7EcZZBQh+0T76UglZFIdQ1UghMwoTCh57HkzXF+FaF0NOJlJLNeNApiCpWOglXSGA9AQAZtuhz0i75gEQBj3MNxRrFrVMKBHMXEhAQqfSdJ193AbmtSKm6x0J6ZCIAGaHAFG+1kqOIT8bXxVJyc+BMOi0omS+AJMl0W4IhuzMrwwAksUM0mm1Pjhd/G+JOp4uCkhW81cGAGEyggx6LUaoE2Mk0Ylm26u/Qkz6lgKCGAkbEFhlqBNkYMPtrAmAoLH2RwRNrj7lHCMcgSrLWi4gCyYEtV421j84ocF1VjNISlTi4j4hMyM6qkM0PAEirm84bQAEQuCorFEawy8I6GWNBcho78DEiEZ+zvAi5ygZ+tchDO5vhewLwPPBPgzua9EALxWGvKxpByDaOwDWsgBCt46Y3SCKYhQXCHW4ocZkCL1u7Bw72wHLLXMx+FF829376b9xdMNvYMjLRuRcD6LdiZTWuqAUpmL7tAMQbj8HlpVEQ2e4haKQm4GEvnb4dCcUn3/8ujvDhpwVdZpBM9LZA99nRzSVhySQs6IWOptlWpVXYzICiXUAwBzVMU6JGODG8CcegLPdCHd0TehPCh5YAfsPVl/SizkeXov8+5ZP++zL54cQOHZK69KgqiqndL5gyJNtNR0FIa7wj3mG4P3sCKwLbhqfaJiMKNn4KFIKc9Gz4z0ET7RrmhzpdEgtnY28NUtR+IPVM0K1/Ue/RPjMOQ0LQIcqhTt1a/hItMlW4SKMWgZjxuC+VhR89y4IDRKRENBsFlz3xHrkrqqH13UYgf+cRsTdCyUQgmQxI8Wei9S5s2Fzzp8Rvx+Z5n0tUPxBrRToqvce8+gu6HqQwIMAxVWFgwdaETj2JaxfK5144THbAdNsx0iXh5lBRJNe/rqs6N/nwfnmT7TSnwzQwZGWmORXDjMjYadVtKsPA7s/vnwGJkkQOt0VUR4APHsOwtd2TGv22wWp+0cAqOG2QYDf1xqk758fItR+7orRWCUQQqRnQPMTG0hO1mR/EH27msAxWSsDNNZ4W08BF60NCll5j3X0CIhmxQWRz4+j5/XdKP7Zg1cEgO5X3klqhVlLv4Hrf/tjzUqvf9deeBoPaOjOfoDfA7MaB0BNoK1tr63ibRA9NvqhntcakHF7JdIqb5lxAGKeIcQ8Q5rXUm+eo018zvWg+7UGqJGoVmHU5PUFm/5fDl1sbiq9yYyE/SbBE2fQtX0nlHDkmih/3dveShL8OMysvn4XH/drAlDvdzUD6itag3b9dRfcW9+46pXvefP9pO9JjLeFLxK3XyjBeVRZflno9HVEtGA0cT77/N+QYs9D7l2Lp75m10kw5GRqEqikNDwzvmk7eKAVnc+/qhkcmbmfgO01fMQfD4rGJqnmNOdjKvCc1lqhrXI+Sn7zY2Qsck5ttA+GED7TdUnPCFPKCKnyHz2JU7//c/K0rfIztV7XkwkETjP1eXtezLLllQF4aPQ176eH0f7HFwACMr4xdSBIZlOydbwJ0d32TS8lVZ6Z30FM3aLdE9KQNXw2DFnZDObmZPTy9NNb0N/w4RX3+cEDrTj1+83o29mYTPnjBN5cF2rp0I4LY2yUbLRVLJeInkWSswCmkiIUPXo/Cr+/6oqwvZ433kfnllfh/TTJHkGVPRc2Sm5NGnvG2yrbaHOukwhPjSZIIwMY9MP7ctavgiVJXp7yBse5Hri3vQX3S68n5QjMrJKKJ2t9rk1jBt+JbJZuslU+COKNlAQEALB+/Wbk37sMud9eAkN2xvTU9v4g+nftRfdrDZp5/iLtVRX81OKhz54aN/tMeLu8rWK9AP0agpJHKkHIWFSJnOW1yLpjIVIc+VOyuSLa54Fnz0H07WrCQOMBcCT5STpWeRCETXVDrmcmlH4v5cBEk7X8bgh6gkjcNnZ+Eki9qQSZNVVIr66ApexGGHIyIAwTa4CoMRmyZwj+oycxuK8F5z/8FL62Y9qFTfzMfwEVm2rH8PlJAQAAe9IWVAnoHuPhg1Lj52pjCoyzCpB642yY5xbDVFKElILhTrIwGUEEKKEIlEAI0d4BhE6fQ/BEOwLHvkT4jDtJM0MrzasNYHXzYm/re5dEwC7n0FQjOW1kwSNEeIgEXVrkEwLCoAPp9SMdZzUmg2MyWJYviQleCHYeEL8owsqWmnBb+yUz0Ekdm7OWLyIh1jGwmohsmElhjjLwDljdXudtefuyKfhkD07uoHmGbItpKRPWksCy0W21qVccQQY3q4y/m3z+NxdeVNldEQD+J+/SDQazLW2RAiwHUA9gDhEZpmayWQbQCaCRVW5gPzVN1TniaTk8feFE6W1gVAPsBFExgPSJAsIMGcxeEDoIaGGm/YJ5P/yfnawZBmPqqtDpPj6/O21epl42OFiIEiLMAZEDjEIiWJigA0OAESVCEIxeJu5gcLsEnIwqSsdQ4FD/mgvtq+mQ/wLCXWsJvB1a8QAAAABJRU5ErkJggg==
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