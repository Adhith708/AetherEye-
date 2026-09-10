
import queue
import tkinter as tk
from tkinter import ttk, messagebox
import sys
import platform
import re
import json
import os
import ctypes
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading
import time
import math
import statistics

# For real-time graphing
try:
	import matplotlib
	matplotlib.use('TkAgg')  # Set backend before importing pyplot
	import matplotlib.pyplot as plt
	from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
	from matplotlib.figure import Figure
	import matplotlib.animation as animation
	MATPLOTLIB_AVAILABLE = True
	print("✅ Matplotlib initialized successfully")
except ImportError as e:
	MATPLOTLIB_AVAILABLE = False
	print(f"❌ Matplotlib not available: {e}")

# For threat detection
import hashlib
import ipaddress

try:
	from scapy.all import AsyncSniffer, get_if_list, IP, TCP, UDP, DNS, DNSQR, Raw
	from scapy.config import conf as scapy_conf
except Exception:
	AsyncSniffer = None
	get_if_list = None
	IP = TCP = UDP = DNS = DNSQR = Raw = None
	scapy_conf = None

ALL_OPTION = "All Interfaces"


def is_admin():
	"""Check if the script is running with administrator privileges"""
	try:
		return ctypes.windll.shell32.IsUserAnAdmin()
	except:
		return False


def run_as_admin():
	"""Restart the script with administrator privileges"""
	if is_admin():
		return True
	else:
		try:
			# Re-run the script with admin privileges
			ctypes.windll.shell32.ShellExecuteW(
				None, 
				"runas", 
				sys.executable, 
				f'"{os.path.abspath(__file__)}"', 
				None, 
				1
			)
			# Exit current instance to prevent duplicate windows
			sys.exit(0)
		except Exception as e:
			print(f"Failed to run as administrator: {e}")
			return False


class PacketSnifferGUI:
	def __init__(self, root: tk.Tk) -> None:
		self.root = root
		self.root.title("Network Monitoring")
		self.sniffer = None
		self.sniffers = []  # when monitoring all interfaces
		self.packet_queue: "queue.Queue[str]" = queue.Queue()
		self.interface_map = {}  # Maps display names to actual interface names
		self.is_paused = False  # Pause state for packet capture
		
		# Browser activity tracking
		self.browser_activity = defaultdict(list)  # device_ip -> list of activities
		self.device_info = {}  # device_ip -> device info
		self.http_requests = []  # Store HTTP requests
		
		# Performance and stability settings
		self.max_activities_per_device = 200  # Reduced to prevent memory issues
		self.max_http_requests = 1000  # Reduced to prevent memory issues
		self.update_lock = threading.Lock()  # Thread safety
		self.last_cleanup = time.time()
		self.cleanup_interval = 10  # More frequent cleanup
		self.packet_count = 0
		self.max_packets_per_second = 50  # Reduced packet processing rate
		self.max_packets_in_tree = 500  # Reduced packets in treeview
		self.packet_data = {}  # Store packet data for details
		self.graph_update_count = 0  # Track graph updates
		self.stop_requested = False  # Flag to signal stop
		self.sniffer_thread = None  # Track sniffer thread
		
		# Real-time statistics and threat detection
		self.traffic_stats = {
			'packets_per_second': deque(maxlen=60),  # Last 60 seconds
			'bytes_per_second': deque(maxlen=60),
			'protocol_counts': defaultdict(int),
			'top_ips': defaultdict(int),
			'top_ports': defaultdict(int),
			'connection_attempts': defaultdict(int),
			'suspicious_activities': []
		}
		
		# Initialize packet rate tracking
		self.packets_this_second = 0
		self.bytes_this_second = 0
		self.last_stats_update = time.time()
		
		# Threat detection patterns
		self.threat_patterns = {
			'port_scan_threshold': 10,  # Ports scanned in 1 minute
			'brute_force_threshold': 5,  # Failed attempts per minute
			'ddos_threshold': 100,  # Packets per second from single IP
			'suspicious_ports': [22, 23, 135, 139, 445, 1433, 3389],  # Common attack ports
			'malicious_ips': set(),  # Known malicious IPs
			'suspicious_domains': set()  # Known malicious domains
		}
		
		# Alert system
		self.alerts = deque(maxlen=1000)  # Store last 1000 alerts
		self.alert_levels = {'LOW': '🟡', 'MEDIUM': '🟠', 'HIGH': '🔴', 'CRITICAL': '🚨'}
		self.alert_sound_enabled = False
		
		self._build_ui()
		self._populate_interfaces()
		self._drain_queue_periodically()
		self._periodic_browser_update()
		
		# Add graceful shutdown handler
		self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
		
		# Apply dark theme
		self._apply_dark_theme()

	def _build_ui(self) -> None:
		main = ttk.Frame(self.root, padding=10)
		main.grid(row=0, column=0, sticky="nsew")
		self.root.columnconfigure(0, weight=1)
		self.root.rowconfigure(0, weight=1)

		# Interface selection
		iface_label = ttk.Label(main, text="Interface:")
		iface_label.grid(row=0, column=0, sticky="w")
		self.iface_var = tk.StringVar()
		self.iface_combo = ttk.Combobox(main, textvariable=self.iface_var, state="readonly", width=40)
		self.iface_combo.grid(row=0, column=1, sticky="ew", padx=(6, 0))
		main.columnconfigure(1, weight=1)

		# Filters
		cap_label = ttk.Label(main, text="Capture filter (BPF):")
		cap_label.grid(row=0, column=2, sticky="e", padx=(10, 4))
		self.capture_filter_var = tk.StringVar()
		self.capture_filter_entry = ttk.Entry(main, textvariable=self.capture_filter_var, width=28)
		self.capture_filter_entry.grid(row=0, column=3, sticky="ew")

		display_label = ttk.Label(main, text="Display filter:")
		display_label.grid(row=1, column=0, sticky="w")
		self.display_filter_var = tk.StringVar()
		self.display_filter_entry = ttk.Entry(main, textvariable=self.display_filter_var, width=40)
		self.display_filter_entry.grid(row=1, column=1, columnspan=2, sticky="ew", padx=(6, 0))

		# Controls
		self.start_btn = ttk.Button(main, text="Start Monitoring", command=self.start_sniffing)
		self.start_btn.grid(row=1, column=3, padx=(8, 8), sticky="e")
		self.pause_btn = ttk.Button(main, text="Pause", command=self.pause_sniffing, state="disabled")
		self.pause_btn.grid(row=1, column=4, padx=(4, 4), sticky="w")
		self.stop_btn = ttk.Button(main, text="Stop Monitoring", command=self.stop_sniffing, state="disabled")
		self.stop_btn.grid(row=1, column=5, sticky="w")

		# Banner (pcap/admin notices)
		self.banner_var = tk.StringVar(value="")
		self.banner = ttk.Label(main, textvariable=self.banner_var, anchor="w")
		self.banner.grid(row=2, column=0, columnspan=6, sticky="ew", pady=(8, 0))

		# Create notebook for tabs
		notebook = ttk.Notebook(main)
		notebook.grid(row=3, column=0, columnspan=6, sticky="nsew", pady=(6, 0))
		main.rowconfigure(3, weight=1)
		
		# Packet capture tab
		packet_frame = ttk.Frame(notebook)
		notebook.add(packet_frame, text="Packet Capture")
		
		# Browser activity tab
		browser_frame = ttk.Frame(notebook)
		notebook.add(browser_frame, text="Browser Activity")
		
		# Dashboard tab
		dashboard_frame = ttk.Frame(notebook)
		notebook.add(dashboard_frame, text="Dashboard")
		
		# Packet list with selection capability
		packet_list_frame = ttk.Frame(packet_frame)
		packet_list_frame.pack(fill="both", expand=True)
		
		# Packet list with scrollbar
		list_frame = ttk.Frame(packet_list_frame)
		list_frame.pack(fill="both", expand=True)
		
		# Create Treeview for packet list
		columns = ("Time", "Source", "Destination", "Protocol", "Info")
		self.packet_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
		
		# Configure columns
		self.packet_tree.heading("Time", text="Time")
		self.packet_tree.heading("Source", text="Source IP")
		self.packet_tree.heading("Destination", text="Destination IP")
		self.packet_tree.heading("Protocol", text="Protocol")
		self.packet_tree.heading("Info", text="Info")
		
		# Set column widths
		self.packet_tree.column("Time", width=80, minwidth=80)
		self.packet_tree.column("Source", width=120, minwidth=120)
		self.packet_tree.column("Destination", width=120, minwidth=120)
		self.packet_tree.column("Protocol", width=80, minwidth=80)
		self.packet_tree.column("Info", width=200, minwidth=200)
		
		# Add scrollbars
		packet_scroll_y = ttk.Scrollbar(list_frame, orient="vertical", command=self.packet_tree.yview)
		packet_scroll_x = ttk.Scrollbar(list_frame, orient="horizontal", command=self.packet_tree.xview)
		self.packet_tree.configure(yscrollcommand=packet_scroll_y.set, xscrollcommand=packet_scroll_x.set)
		
		# Pack treeview and scrollbars
		self.packet_tree.pack(side="left", fill="both", expand=True)
		packet_scroll_y.pack(side="right", fill="y")
		packet_scroll_x.pack(side="bottom", fill="x")
		
		# Bind click events for filtering
		self.packet_tree.bind("<Button-1>", self._on_packet_click)
		self.packet_tree.bind("<Double-1>", self._on_packet_double_click)
		
		# Packet details area
		details_frame = ttk.LabelFrame(packet_list_frame, text="Packet Details", padding=5)
		details_frame.pack(fill="x", pady=(5, 0))
		
		self.text = tk.Text(details_frame, height=8, wrap="none", bg="#0b0e11", fg="#e6edf3", insertbackground="#e6edf3")
		self.text.pack(fill="both", expand=True)
		scroll_y = ttk.Scrollbar(details_frame, orient="vertical", command=self.text.yview)
		scroll_y.pack(side="right", fill="y")
		self.text.configure(yscrollcommand=scroll_y.set)
		
		# Browser activity area
		browser_controls = ttk.Frame(browser_frame)
		browser_controls.pack(fill="x", pady=(0, 5))
		
		ttk.Label(browser_controls, text="Connected Devices:").pack(side="left")
		self.device_combo = ttk.Combobox(browser_controls, state="readonly", width=20)
		self.device_combo.pack(side="left", padx=(5, 10))
		self.device_combo.bind("<<ComboboxSelected>>", self._on_device_selected)
		
		ttk.Button(browser_controls, text="Clear Activity", command=self._clear_browser_activity).pack(side="left", padx=(5, 0))
		ttk.Button(browser_controls, text="Export Data", command=self._export_browser_data).pack(side="left", padx=(5, 0))
		
		# Browser activity display
		self.browser_text = tk.Text(browser_frame, height=20, wrap="none", bg="#f8f9fa", fg="#212529", insertbackground="#212529")
		self.browser_text.pack(fill="both", expand=True)
		browser_scroll_y = ttk.Scrollbar(browser_frame, orient="vertical", command=self.browser_text.yview)
		browser_scroll_y.pack(side="right", fill="y")
		self.browser_text.configure(yscrollcommand=browser_scroll_y.set)
		
		# Dashboard UI
		self._build_dashboard_ui(dashboard_frame)
		# Color tags
		self.text.tag_configure("TCP", foreground="#4FC3F7")
		self.text.tag_configure("UDP", foreground="#66BB6A")
		self.text.tag_configure("DNS", foreground="#BA68C8")
		self.text.tag_configure("HTTP", foreground="#FFA726")
		self.text.tag_configure("INFO", foreground="#9AA4AF")
		self.text.tag_configure("ERROR", foreground="#EF5350")

		# Status
		self.status_var = tk.StringVar(value="Ready")
		status = ttk.Label(main, textvariable=self.status_var, anchor="w")
		status.grid(row=4, column=0, columnspan=6, sticky="ew", pady=(8, 0))

	def _populate_interfaces(self) -> None:
		if get_if_list is None:
			self._append_text("Scapy is not available. Please install scapy.\n")
			return
		try:
			# Get interfaces from Scapy
			scapy_interfaces = get_if_list() if get_if_list else []
			
			# Get interfaces from psutil for better names
			try:
				import psutil
				psutil_interfaces = {}
				for name, addrs in psutil.net_if_addrs().items():
					ip_addrs = [addr.address for addr in addrs if addr.family == 2]  # IPv4
					if ip_addrs:
						psutil_interfaces[name] = ip_addrs[0]
			except ImportError:
				psutil_interfaces = {}
			
			# Create interface list with better names
			interface_list = []
			interface_map = {}
			
			# Add "All Interfaces" option
			interface_list.append(ALL_OPTION)
			
			# Process each Scapy interface
			for iface in scapy_interfaces:
				# Try to find a matching psutil interface
				display_name = iface
				ip_addr = ""
				
				# Look for matching interface by name or IP
				for psutil_name, psutil_ip in psutil_interfaces.items():
					if (iface.lower() in psutil_name.lower() or 
						psutil_name.lower() in iface.lower() or
						any(iface in addr for addr in [psutil_ip])):
						display_name = f"{psutil_name} ({psutil_ip})" if psutil_ip else psutil_name
						ip_addr = psutil_ip
						break
				
				# If no match found, try to extract IP from interface name
				if not ip_addr and "\\Device\\NPF_" in iface:
					# This is a Windows Npcap interface, try to find corresponding IP
					for psutil_name, psutil_ip in psutil_interfaces.items():
						if psutil_ip:  # Only interfaces with IP addresses
							display_name = f"{psutil_name} ({psutil_ip})"
							ip_addr = psutil_ip
							break
				
				interface_list.append(display_name)
				interface_map[display_name] = iface
			
			# If no Scapy interfaces found, try to use psutil interfaces directly
			if not scapy_interfaces and psutil_interfaces:
				for name, ip in psutil_interfaces.items():
					display_name = f"{name} ({ip})" if ip else name
					interface_list.append(display_name)
					interface_map[display_name] = name
			
			# Update the combo box
			self.iface_combo["values"] = interface_list
			self.interface_map = interface_map
			
			if interface_list:
				self.iface_combo.current(0)
				self.status_var.set(f"Detected {len(interface_list)-1} network interfaces")
			else:
				self.status_var.set("No interfaces detected.")
			
			# Show banner if pcap provider likely missing
			if platform.system() == "Windows" and scapy_conf is not None and not getattr(scapy_conf, "use_pcap", False):
				self.banner_var.set("⚠️ Npcap/libpcap not detected. Install Npcap (WinPcap-compatible mode) and run as Administrator for full functionality.")
			else:
				self.banner_var.set("✅ Ready for packet capture")
				
		except Exception as e:
			self._append_text(f"Failed to list interfaces: {e}\n")
			self.status_var.set("Error detecting interfaces")

	def _append_text(self, line: str, tag: str = "INFO") -> None:
		self.text.insert("end", line, tag)
		self.text.see("end")

	def _packet_to_line(self, packet) -> tuple[str, str, dict]:
		try:
			if IP in packet:
				src_ip = packet[IP].src
				dst_ip = packet[IP].dst
				proto = packet[IP].proto
				parts = [f"{src_ip} -> {dst_ip}", f"Protocol: {proto}"]
				tag = "INFO"
				protocol = "IP"
				info = f"{src_ip} -> {dst_ip}"
				
				if TCP in packet:
					dport = packet[TCP].dport
					sport = packet[TCP].sport
					parts.append(f"TCP dport: {dport}")
					tag = "TCP"
					protocol = "TCP"
					info = f"TCP {src_ip}:{sport} -> {dst_ip}:{dport}"
					
					if Raw in packet:
						payload = packet[Raw].load.decode(errors="ignore")
						if "HTTP" in payload:
							parts.append(f"HTTP: {payload[:100]}")
							tag = "HTTP"
							protocol = "HTTP"
							info = f"HTTP {src_ip} -> {dst_ip}"
							# Track browser activity
							self._analyze_http_traffic(packet, payload)
				elif UDP in packet:
					dport = packet[UDP].dport
					sport = packet[UDP].sport
					parts.append(f"UDP dport: {dport}")
					tag = "UDP"
					protocol = "UDP"
					info = f"UDP {src_ip}:{sport} -> {dst_ip}:{dport}"
					
					if DNS in packet and packet[DNS].opcode == 0 and packet[DNS].qd:
						domain = packet[DNSQR].qname.decode()
						parts.append(f"DNS Query: {domain}")
						tag = "DNS"
						protocol = "DNS"
						info = f"DNS Query: {domain}"
						# Track DNS queries for device identification
						self._track_dns_query(src_ip, domain)
				
				# Create packet data for treeview
				packet_info = {
					'time': datetime.now().strftime('%H:%M:%S'),
					'source': src_ip,
					'destination': dst_ip,
					'protocol': protocol,
					'info': info,
					'details': " | ".join(parts),
					'raw_packet': packet
				}
				
				return " | ".join(parts), tag, packet_info
		except Exception as e:
			error_info = {
				'time': datetime.now().strftime('%H:%M:%S'),
				'source': 'Unknown',
				'destination': 'Unknown',
				'protocol': 'Error',
				'info': f'Parse error: {e}',
				'details': f'Parse error: {e}',
				'raw_packet': None
			}
			return f"Parse error: {e}", "ERROR", error_info
		return "", "INFO", {}

	def _enqueue_packet(self, packet) -> None:
		try:
			# Check if stop was requested
			if self.stop_requested:
				return
			
			# Check if paused
			if self.is_paused:
				return
			
			# Rate limiting to prevent system overload
			current_time = time.time()
			if hasattr(self, 'last_packet_time'):
				time_diff = current_time - self.last_packet_time
				if time_diff < 1.0 / self.max_packets_per_second:
					return  # Skip this packet to maintain rate limit
			self.last_packet_time = current_time
			
			line, tag, packet_info = self._packet_to_line(packet)
			if not line or not packet_info:
				return
			# Apply display filter (very simple syntax similar to Wireshark-lite)
			expr = (self.display_filter_var.get().strip() or "")
			if expr:
				if not self._matches_display_filter(packet, expr):
					return
			
			# Limit queue size to prevent memory issues
			if self.packet_queue.qsize() < 500:  # Reduced queue size
				self.packet_queue.put((line, tag, packet_info))
		except Exception as e:
			# Silently ignore packet processing errors to prevent crashes
			pass

	def _matches_display_filter(self, packet, expr: str) -> bool:
		"""Support a tiny subset: tcp, udp, dns, http, ip.addr contains X, tcp.port==N, udp.port==N, and 'and/or'."""
		try:
			text = expr.lower()
			result = True
			clauses = [c.strip() for c in text.replace(" or ", "|OR|").split("|OR|")]
			any_ok = False
			for clause in clauses:
				ands = [c.strip() for c in clause.split(" and ")]
				all_ok = True
				for term in ands:
					ok = False
					if term == "tcp":
						ok = TCP in packet
					elif term == "udp":
						ok = UDP in packet
					elif term == "dns":
						ok = DNS in packet
					elif term == "http":
						ok = Raw in packet and b"HTTP" in packet[Raw].load
					elif term.startswith("ip.addr contains "):
						needle = term.replace("ip.addr contains ", "").strip()
						if IP in packet:
							ok = needle in (packet[IP].src + packet[IP].dst)
					elif term.startswith("tcp.port=="):
						try:
							port = int(term.split("==",1)[1])
							ok = TCP in packet and (packet[TCP].sport == port or packet[TCP].dport == port)
						except Exception:
							ok = False
					elif term.startswith("udp.port=="):
						try:
							port = int(term.split("==",1)[1])
							ok = UDP in packet and (packet[UDP].sport == port or packet[UDP].dport == port)
						except Exception:
							ok = False
					else:
						# Fallback: substring match on payload
						if Raw in packet:
							try:
								ok = term in packet[Raw].load.decode(errors="ignore").lower()
							except Exception:
								ok = False
					all_ok = all_ok and ok
				if all_ok:
					any_ok = True
			return any_ok if clauses else True
		except Exception:
			return True

	def _drain_queue_periodically(self) -> None:
		try:
			# Process up to 20 packets at a time to prevent UI freezing
			processed = 0
			while processed < 20:
				try:
					line, tag, packet_info = self.packet_queue.get_nowait()
					
					# Add to treeview
					self._add_packet_to_tree(packet_info)
					
					# Update traffic statistics
					self._update_traffic_stats(packet_info)
					
					# Detect threats
					self._detect_threats(packet_info)
					
					# Also add to text area for details
					self._append_text(line + "\n", tag)
					processed += 1
				except queue.Empty:
					break
		except Exception as e:
			# Silently ignore queue processing errors
			pass
		finally:
			# Schedule next update with longer interval
			self.root.after(200, self._drain_queue_periodically)

	def start_sniffing(self) -> None:
		if AsyncSniffer is None:
			messagebox.showerror("Error", "Scapy is not installed. pip install scapy")
			return
		iface = self.iface_var.get().strip()
		if not iface:
			messagebox.showwarning("Interface required", "Please select an interface")
			return
		if self.sniffer is not None or self.sniffers:
			messagebox.showinfo("Already running", "Sniffer is already running")
			return
		try:
			cap_filter = self.capture_filter_var.get().strip() or None
			if iface == ALL_OPTION:
				# Start a sniffer on each interface
				interfaces = []
				try:
					interfaces = get_if_list()
				except Exception:
					interfaces = []
				started = 0
				for ifn in interfaces:
					try:
						sn = AsyncSniffer(iface=ifn, prn=self._enqueue_packet, store=False, filter=cap_filter)
						sn.start()
						self.sniffers.append(sn)
						started += 1
					except Exception:
						pass
				if started == 0:
					raise RuntimeError("Failed to start on any interface")
				self.status_var.set(f"Sniffing on all interfaces ({started})...")
			else:
				# Use the interface mapping to get the actual interface name
				actual_iface = self.interface_map.get(iface, iface)
				self.sniffer = AsyncSniffer(iface=actual_iface, prn=self._enqueue_packet, store=False, filter=cap_filter)
				self.sniffer.start()
				self.status_var.set(f"Sniffing on {iface}...")
			self.start_btn.configure(state="disabled")
			self.pause_btn.configure(state="normal")
			self.stop_btn.configure(state="normal")
		except Exception as e:
			# Cleanup on failure
			for sn in self.sniffers:
				try:
					sn.stop()
				except Exception:
					pass
			self.sniffers = []
			self.sniffer = None
			messagebox.showerror("Failed to start", str(e))

	def stop_sniffing(self) -> None:
		"""Stop packet sniffing and clean up resources"""
		try:
			# Update UI immediately to show stopping
			self.status_var.set("Stopping...")
			self.root.update_idletasks()
			
			# Force stop immediately to prevent hanging
			self._force_stop_all()
			
			# Update UI
			self._update_ui_after_stop()
			
		except Exception as e:
			print(f"Stop error: {e}")
			# Ensure UI is responsive even if cleanup fails
			self.status_var.set("Stopped (with errors)")
			self.start_btn.configure(state="normal")
			self.stop_btn.configure(state="disabled")
			self.pause_btn.configure(state="disabled")
			self.is_paused = False
			self.root.update_idletasks()

	def _force_stop_all(self) -> None:
		"""Force stop all sniffers and clean up resources"""
		try:
			# Set stop flag
			self.stop_requested = True
			
			# Stop main sniffer
			if self.sniffer is not None:
				try:
					if hasattr(self.sniffer, 'stop'):
						self.sniffer.stop()
					elif hasattr(self.sniffer, 'join'):
						self.sniffer.join(timeout=1)
				except Exception as e:
					print(f"Error stopping main sniffer: {e}")
				finally:
					self.sniffer = None
			
			# Stop all sniffers in list
			if self.sniffers:
				for sn in self.sniffers:
					try:
						if hasattr(sn, 'stop'):
							sn.stop()
						elif hasattr(sn, 'join'):
							sn.join(timeout=1)
					except Exception as e:
						print(f"Error stopping sniffer: {e}")
				self.sniffers = []
			
			# Clear packet queue to free memory
			try:
				while not self.packet_queue.empty():
					self.packet_queue.get_nowait()
			except:
				pass
			
			# Reset state
			self.is_paused = False
			
		except Exception as e:
			print(f"Force stop error: {e}")

	def _update_ui_after_stop(self) -> None:
		"""Update UI after successful stop"""
		self.status_var.set("Stopped")
		self.start_btn.configure(state="normal")
		self.pause_btn.configure(state="disabled")
		self.stop_btn.configure(state="disabled")
		self.is_paused = False
		self.root.update_idletasks()

	def _update_ui_after_stop_error(self) -> None:
		"""Update UI after stop with errors"""
		self.status_var.set("Stopped (with errors)")
		self.start_btn.configure(state="normal")
		self.pause_btn.configure(state="disabled")
		self.stop_btn.configure(state="disabled")
		self.is_paused = False
		self.root.update_idletasks()

	def _force_stop_timeout(self) -> None:
		"""Force stop timeout handler"""
		if self.sniffer is not None or self.sniffers:
			print("Force stopping due to timeout...")
			self._force_stop_all()
			self._update_ui_after_stop()

	def pause_sniffing(self) -> None:
		"""Pause packet capture"""
		if not self.is_paused:
			self.is_paused = True
			self.status_var.set("Paused - Click Resume to continue")
			self.pause_btn.configure(text="Resume", command=self.resume_sniffing)
			self.root.update_idletasks()

	def resume_sniffing(self) -> None:
		"""Resume packet capture"""
		if self.is_paused:
			self.is_paused = False
			self.status_var.set("Resumed - Capturing packets...")
			self.pause_btn.configure(text="Pause", command=self.pause_sniffing)
			self.root.update_idletasks()

	def _update_ui_after_stop_error(self) -> None:
		"""Update UI after stop with errors"""
		self.status_var.set("Stopped (with errors)")
		self.start_btn.configure(state="normal")
		self.stop_btn.configure(state="disabled")
		self.root.update_idletasks()

	def _force_stop_timeout(self) -> None:
		"""Force stop if timeout reached"""
		if self.sniffer is not None or self.sniffers:
			self.status_var.set("Force stopped")
			self.start_btn.configure(state="normal")
			self.stop_btn.configure(state="disabled")
			self.root.update_idletasks()

	def _on_closing(self) -> None:
		"""Handle application closing gracefully"""
		try:
			# Stop monitoring if running
			if self.sniffer is not None or self.sniffers:
				self.stop_sniffing()
			
			# Give a moment for cleanup
			self.root.after(100, self.root.destroy)
		except Exception:
			# Force close if graceful shutdown fails
			self.root.destroy()

	def _analyze_http_traffic(self, packet, payload: str) -> None:
		"""Analyze HTTP traffic for browser activity"""
		try:
			# Periodic cleanup to prevent memory issues
			current_time = time.time()
			if current_time - self.last_cleanup > self.cleanup_interval:
				self._cleanup_old_data()
				self.last_cleanup = current_time
			
			if IP in packet:
				src_ip = packet[IP].src
				dst_ip = packet[IP].dst
				
				# Extract HTTP method and URL
				lines = payload.split('\n')
				if lines:
					request_line = lines[0].strip()
					if request_line.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
						parts = request_line.split(' ')
						if len(parts) >= 2:
							method = parts[0]
							url = parts[1]
							
							# Extract headers (limit to first 20 lines to prevent memory issues)
							headers = {}
							for line in lines[1:21]:  # Limit header parsing
								if ':' in line and not line.startswith('HTTP/'):
									try:
										key, value = line.split(':', 1)
										headers[key.strip().lower()] = value.strip()
									except:
										continue
							
							# Create activity record
							activity = {
								'timestamp': datetime.now().strftime('%H:%M:%S'),
								'method': method,
								'url': url[:200],  # Limit URL length
								'host': headers.get('host', dst_ip)[:100],  # Limit host length
								'user_agent': headers.get('user-agent', 'Unknown')[:200],  # Limit user agent length
								'dst_ip': dst_ip,
								'referer': headers.get('referer', '')[:200]  # Limit referer length
							}
							
							# Thread-safe storage
							with self.update_lock:
								# Store activity with limits
								if len(self.browser_activity[src_ip]) >= self.max_activities_per_device:
									self.browser_activity[src_ip] = self.browser_activity[src_ip][-self.max_activities_per_device//2:]
								
								self.browser_activity[src_ip].append(activity)
								
								# Limit total HTTP requests
								if len(self.http_requests) >= self.max_http_requests:
									self.http_requests = self.http_requests[-self.max_http_requests//2:]
								
								self.http_requests.append(activity)
								
								# Update device info
								if src_ip not in self.device_info:
									self.device_info[src_ip] = {
										'ip': src_ip,
										'user_agent': activity['user_agent'],
										'last_seen': activity['timestamp'],
										'domains': set()
									}
									self._update_device_list()
								
								# Extract domain
								domain = activity['host'].split(':')[0]
								self.device_info[src_ip]['domains'].add(domain)
								self.device_info[src_ip]['last_seen'] = activity['timestamp']
								
								# Update browser activity display more frequently
								if len(self.browser_activity[src_ip]) % 5 == 0:  # Update every 5 requests
									self._update_browser_display()
							
		except Exception as e:
			pass  # Silently ignore parsing errors

	def _cleanup_old_data(self) -> None:
		"""Clean up old data to prevent memory issues"""
		try:
			with self.update_lock:
				# Remove old activities (keep only last 200 per device)
				for device_ip in list(self.browser_activity.keys()):
					if len(self.browser_activity[device_ip]) > self.max_activities_per_device:
						self.browser_activity[device_ip] = self.browser_activity[device_ip][-self.max_activities_per_device//2:]
				
				# Remove old HTTP requests (keep only last 1000)
				if len(self.http_requests) > self.max_http_requests:
					self.http_requests = self.http_requests[-self.max_http_requests//2:]
				
				# Clean up packet data
				if len(self.packet_data) > self.max_packets_in_tree:
					# Keep only recent packets
					keys_to_remove = list(self.packet_data.keys())[:-self.max_packets_in_tree//2]
					for key in keys_to_remove:
						del self.packet_data[key]
				
				# Clean up device info for devices not seen recently
				current_time = datetime.now()
				devices_to_remove = []
				for device_ip, info in self.device_info.items():
					try:
						last_seen = datetime.strptime(info['last_seen'], '%H:%M:%S')
						time_diff = (current_time - last_seen).total_seconds()
						if time_diff > 3600:  # Remove devices not seen for 1 hour
							devices_to_remove.append(device_ip)
					except:
						continue
				
				for device_ip in devices_to_remove:
					if device_ip in self.browser_activity:
						del self.browser_activity[device_ip]
					if device_ip in self.device_info:
						del self.device_info[device_ip]
				
				self._update_device_list()
		except Exception as e:
			pass

	def _track_dns_query(self, src_ip: str, domain: str) -> None:
		"""Track DNS queries for device identification"""
		try:
			# Clean domain name
			domain = domain.rstrip('.')
			
			if src_ip not in self.device_info:
				self.device_info[src_ip] = {
					'ip': src_ip,
					'user_agent': 'Unknown',
					'last_seen': datetime.now().strftime('%H:%M:%S'),
					'domains': set()
				}
				self._update_device_list()
			
			self.device_info[src_ip]['domains'].add(domain)
			self.device_info[src_ip]['last_seen'] = datetime.now().strftime('%H:%M:%S')
			
		except Exception as e:
			pass

	def _update_device_list(self) -> None:
		"""Update the device combo box"""
		try:
			devices = []
			for ip, info in self.device_info.items():
				device_name = f"{ip} ({len(info['domains'])} domains)"
				devices.append(device_name)
			
			self.device_combo['values'] = devices
			if devices and not self.device_combo.get():
				self.device_combo.current(0)
				# Auto-display activity for the first device
				self._update_browser_display()
		except Exception as e:
			pass

	def _on_device_selected(self, event) -> None:
		"""Handle device selection"""
		try:
			selected = self.device_combo.get()
			if selected:
				# Extract IP from selection
				ip = selected.split(' ')[0]
				self._display_device_activity(ip)
		except Exception as e:
			pass

	def _display_device_activity(self, device_ip: str) -> None:
		"""Display browser activity for selected device"""
		try:
			self.browser_text.delete(1.0, tk.END)
			
			if device_ip in self.browser_activity:
				activities = self.browser_activity[device_ip]
				device_info = self.device_info.get(device_ip, {})
				
				# Device header
				header = f"🌐 Device: {device_ip}\n"
				header += f"📱 User Agent: {device_info.get('user_agent', 'Unknown')}\n"
				header += f"⏰ Last Seen: {device_info.get('last_seen', 'Unknown')}\n"
				header += f"🌍 Domains Visited: {len(device_info.get('domains', set()))}\n"
				header += f"📊 Total Activities: {len(activities)}\n"
				header += "=" * 80 + "\n\n"
				
				self.browser_text.insert(tk.END, header)
				
				# Recent activities (last 50)
				recent_activities = activities[-50:]
				for activity in reversed(recent_activities):
					line = f"[{activity['timestamp']}] {activity['method']} {activity['url']}\n"
					line += f"    Host: {activity['host']}\n"
					if activity['referer']:
						line += f"    Referer: {activity['referer']}\n"
					line += "\n"
					self.browser_text.insert(tk.END, line)
			else:
				self.browser_text.insert(tk.END, f"No browser activity found for {device_ip}\n")
				self.browser_text.insert(tk.END, f"Available devices: {list(self.browser_activity.keys())}\n")
				
		except Exception as e:
			self.browser_text.insert(tk.END, f"Error displaying activity: {e}")

	def _update_browser_display(self) -> None:
		"""Update browser activity display"""
		try:
			selected = self.device_combo.get()
			if selected:
				ip = selected.split(' ')[0]
				self._display_device_activity(ip)
		except Exception as e:
			pass

	def _periodic_browser_update(self) -> None:
		"""Periodically update browser activity display"""
		try:
			# Update every 3 seconds
			self.root.after(3000, self._periodic_browser_update)
			
			# Only update if we have devices and a selection
			if self.device_info and self.device_combo.get():
				self._update_browser_display()
		except Exception as e:
			pass

	def _clear_browser_activity(self) -> None:
		"""Clear all browser activity data"""
		try:
			self.browser_activity.clear()
			self.device_info.clear()
			self.http_requests.clear()
			self.device_combo['values'] = []
			self.browser_text.delete(1.0, tk.END)
			self.browser_text.insert(tk.END, "Browser activity cleared.")
		except Exception as e:
			pass

	def _export_browser_data(self) -> None:
		"""Export browser activity data to JSON"""
		try:
			from tkinter import filedialog
			
			filename = filedialog.asksaveasfilename(
				defaultextension=".json",
				filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
			)
			
			if filename:
				export_data = {
					'devices': {},
					'activities': {}
				}
				
				for ip, info in self.device_info.items():
					export_data['devices'][ip] = {
						'ip': info['ip'],
						'user_agent': info['user_agent'],
						'last_seen': info['last_seen'],
						'domains': list(info['domains'])
					}
				
				for ip, activities in self.browser_activity.items():
					export_data['activities'][ip] = activities
				
				with open(filename, 'w') as f:
					json.dump(export_data, f, indent=2)
				
				messagebox.showinfo("Export Complete", f"Browser activity data exported to {filename}")
				
		except Exception as e:
			messagebox.showerror("Export Error", f"Failed to export data: {e}")

	def _build_dashboard_ui(self, parent) -> None:
		"""Build the dashboard UI with graphs and alerts"""
		try:
			# Top frame for statistics
			stats_frame = ttk.LabelFrame(parent, text="Network Statistics", padding=10)
			stats_frame.pack(fill="x", pady=(0, 10))
			
			# Statistics labels
			stats_grid = ttk.Frame(stats_frame)
			stats_grid.pack(fill="x")
			
			# Row 1: Traffic stats
			ttk.Label(stats_grid, text="Packets/sec:").grid(row=0, column=0, sticky="w", padx=(0, 10))
			self.packets_per_sec_var = tk.StringVar(value="0")
			ttk.Label(stats_grid, textvariable=self.packets_per_sec_var, font=("Arial", 12, "bold")).grid(row=0, column=1, sticky="w", padx=(0, 20))
			
			ttk.Label(stats_grid, text="Bytes/sec:").grid(row=0, column=2, sticky="w", padx=(0, 10))
			self.bytes_per_sec_var = tk.StringVar(value="0")
			ttk.Label(stats_grid, textvariable=self.bytes_per_sec_var, font=("Arial", 12, "bold")).grid(row=0, column=3, sticky="w", padx=(0, 20))
			
			ttk.Label(stats_grid, text="Total Packets:").grid(row=0, column=4, sticky="w", padx=(0, 10))
			self.total_packets_var = tk.StringVar(value="0")
			ttk.Label(stats_grid, textvariable=self.total_packets_var, font=("Arial", 12, "bold")).grid(row=0, column=5, sticky="w")
			
			# Row 2: Protocol distribution
			ttk.Label(stats_grid, text="Top Protocol:").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(10, 0))
			self.top_protocol_var = tk.StringVar(value="None")
			ttk.Label(stats_grid, textvariable=self.top_protocol_var, font=("Arial", 10, "bold")).grid(row=1, column=1, sticky="w", padx=(0, 20), pady=(10, 0))
			
			ttk.Label(stats_grid, text="Top IP:").grid(row=1, column=2, sticky="w", padx=(0, 10), pady=(10, 0))
			self.top_ip_var = tk.StringVar(value="None")
			ttk.Label(stats_grid, textvariable=self.top_ip_var, font=("Arial", 10, "bold")).grid(row=1, column=3, sticky="w", padx=(0, 20), pady=(10, 0))
			
			ttk.Label(stats_grid, text="Alerts:").grid(row=1, column=4, sticky="w", padx=(0, 10), pady=(10, 0))
			self.alert_count_var = tk.StringVar(value="0")
			ttk.Label(stats_grid, textvariable=self.alert_count_var, font=("Arial", 10, "bold"), foreground="red").grid(row=1, column=5, sticky="w", pady=(10, 0))
			
			# Main content area
			content_frame = ttk.Frame(parent)
			content_frame.pack(fill="both", expand=True)
			
			# Left side: Graphs
			graphs_frame = ttk.LabelFrame(content_frame, text="Real-time Graphs", padding=10)
			graphs_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))
			
			if MATPLOTLIB_AVAILABLE:
				try:
					# Create matplotlib figure
					self.fig = Figure(figsize=(8, 6), dpi=100)
					self.ax1 = self.fig.add_subplot(211)
					self.ax2 = self.fig.add_subplot(212)
					
					# Create canvas
					self.canvas = FigureCanvasTkAgg(self.fig, graphs_frame)
					self.canvas.get_tk_widget().pack(fill="both", expand=True)
					
					# Initialize graphs
					self._init_graphs()
					print("✅ Graphs created successfully")
				except Exception as e:
					print(f"❌ Error creating graphs: {e}")
					ttk.Label(graphs_frame, text=f"Graph Error: {str(e)[:100]}", 
							 foreground="red").pack(expand=True)
			else:
				# Fallback if matplotlib not available
				ttk.Label(graphs_frame, text="Matplotlib not available. Install with: pip install matplotlib", 
						 foreground="red").pack(expand=True)
			
			# Right side: Alerts and threats
			alerts_frame = ttk.LabelFrame(content_frame, text="Security Alerts", padding=10)
			alerts_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))
			
			# Alert controls
			alert_controls = ttk.Frame(alerts_frame)
			alert_controls.pack(fill="x", pady=(0, 10))
			
			ttk.Button(alert_controls, text="Clear Alerts", command=self._clear_alerts).pack(side="left")
			ttk.Button(alert_controls, text="Export Alerts", command=self._export_alerts).pack(side="left", padx=(5, 0))
			ttk.Button(alert_controls, text="Test Alert", command=self._test_alert).pack(side="left", padx=(5, 0))
			
			# Alert list
			self.alert_listbox = tk.Listbox(alerts_frame, height=15, font=("Consolas", 9))
			alert_scroll = ttk.Scrollbar(alerts_frame, orient="vertical", command=self.alert_listbox.yview)
			self.alert_listbox.configure(yscrollcommand=alert_scroll.set)
			
			self.alert_listbox.pack(side="left", fill="both", expand=True)
			alert_scroll.pack(side="right", fill="y")
			
			# Threat detection status
			threat_frame = ttk.LabelFrame(parent, text="Threat Detection Status", padding=10)
			threat_frame.pack(fill="x", pady=(10, 0))
			
			threat_grid = ttk.Frame(threat_frame)
			threat_grid.pack(fill="x")
			
			ttk.Label(threat_grid, text="Port Scan Detection:").grid(row=0, column=0, sticky="w", padx=(0, 10))
			self.port_scan_status = tk.StringVar(value="🟢 Active")
			ttk.Label(threat_grid, textvariable=self.port_scan_status).grid(row=0, column=1, sticky="w", padx=(0, 20))
			
			ttk.Label(threat_grid, text="DDoS Detection:").grid(row=0, column=2, sticky="w", padx=(0, 10))
			self.ddos_status = tk.StringVar(value="🟢 Active")
			ttk.Label(threat_grid, textvariable=self.ddos_status).grid(row=0, column=3, sticky="w", padx=(0, 20))
			
			ttk.Label(threat_grid, text="Suspicious Activity:").grid(row=0, column=4, sticky="w", padx=(0, 10))
			self.suspicious_status = tk.StringVar(value="🟢 Active")
			ttk.Label(threat_grid, textvariable=self.suspicious_status).grid(row=0, column=5, sticky="w")
			
		except Exception as e:
			ttk.Label(parent, text=f"Error building dashboard: {e}", foreground="red").pack(expand=True)

	def _init_graphs(self) -> None:
		"""Initialize the real-time graphs"""
		try:
			# Set dark theme for matplotlib
			plt.style.use('dark_background')
			self.fig.patch.set_facecolor('#1e1e1e')
			
			# Packet rate graph
			self.ax1.set_title("Packets per Second", color='white', fontsize=12, fontweight='bold')
			self.ax1.set_ylabel("Packets/sec", color='white', fontsize=10)
			self.ax1.set_xlabel("Time (seconds)", color='white', fontsize=10)
			self.ax1.grid(True, alpha=0.3, color='gray')
			self.ax1.set_ylim(0, 50)  # Set initial y-axis limit
			self.ax1.tick_params(colors='white', labelsize=9)
			self.ax1.set_facecolor('#1e1e1e')
			
			# Protocol distribution graph
			self.ax2.set_title("Protocol Distribution", color='white', fontsize=12, fontweight='bold')
			self.ax2.set_ylabel("Count", color='white', fontsize=10)
			self.ax2.set_xlabel("Protocol", color='white', fontsize=10)
			self.ax2.grid(True, alpha=0.3, color='gray')
			self.ax2.tick_params(colors='white', labelsize=9)
			self.ax2.set_facecolor('#1e1e1e')
			
			# Initialize with sample data to show the graphs
			sample_data = [0, 1, 2, 1, 3, 2, 4, 3, 2, 1, 5, 3, 4, 2, 1, 0, 2, 3, 4, 2]
			time_axis = list(range(len(sample_data)))
			self.ax1.plot(time_axis, sample_data, '#4FC3F7', linewidth=2, marker='o', markersize=3, label='Packets/sec')
			self.ax1.legend(loc='upper right', fontsize=8)
			
			# Sample protocol data
			protocols = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP']
			counts = [15, 12, 8, 6, 4]
			colors = ['#4FC3F7', '#66BB6A', '#BA68C8', '#FFA726', '#FF7043']
			self.ax2.bar(protocols, counts, color=colors)
			
			# Start animation
			self.ani = animation.FuncAnimation(self.fig, self._update_graphs, interval=1000, blit=False, cache_frame_data=False)
			
			# Force initial draw
			self.canvas.draw()
			
			print("✅ Graphs initialized successfully")
			
		except Exception as e:
			print(f"❌ Graph initialization error: {e}")
			import traceback
			traceback.print_exc()

	def _update_graphs(self, frame) -> None:
		"""Update the real-time graphs"""
		try:
			# Limit graph update frequency to prevent crashes
			self.graph_update_count += 1
			if self.graph_update_count % 2 != 0:  # Update every other frame
				return
			
			# Clear previous plots
			self.ax1.clear()
			self.ax2.clear()
			
			# Set dark theme for each update
			self.ax1.set_facecolor('#1e1e1e')
			self.ax2.set_facecolor('#1e1e1e')
			
			# Plot packet rate
			packet_data = list(self.traffic_stats['packets_per_second'])
			if packet_data and len(packet_data) > 0 and any(p > 0 for p in packet_data):
				# Create time axis
				time_axis = list(range(len(packet_data)))
				self.ax1.plot(time_axis, packet_data, '#4FC3F7', linewidth=2, marker='o', markersize=3, label='Packets/sec')
				self.ax1.set_title("Packets per Second", color='white', fontsize=12, fontweight='bold')
				self.ax1.set_ylabel("Packets/sec", color='white', fontsize=10)
				self.ax1.set_xlabel("Time (seconds)", color='white', fontsize=10)
				self.ax1.grid(True, alpha=0.3, color='gray')
				self.ax1.tick_params(colors='white', labelsize=9)
				self.ax1.legend(loc='upper right', fontsize=8)
				# Auto-scale y-axis
				max_val = max(packet_data)
				if max_val > 0:
					self.ax1.set_ylim(0, max_val * 1.2)
				else:
					self.ax1.set_ylim(0, 10)
			else:
				# Show empty state with sample data
				sample_data = [0, 1, 2, 1, 3, 2, 4, 3, 2, 1, 5, 3, 4, 2, 1, 0, 2, 3, 4, 2]
				time_axis = list(range(len(sample_data)))
				self.ax1.plot(time_axis, sample_data, '#4FC3F7', linewidth=2, marker='o', markersize=3, label='Packets/sec')
				self.ax1.set_title("Packets per Second (Waiting for Data)", color='white', fontsize=12, fontweight='bold')
				self.ax1.set_ylabel("Packets/sec", color='white', fontsize=10)
				self.ax1.set_xlabel("Time (seconds)", color='white', fontsize=10)
				self.ax1.grid(True, alpha=0.3, color='gray')
				self.ax1.tick_params(colors='white', labelsize=9)
				self.ax1.legend(loc='upper right', fontsize=8)
				self.ax1.set_ylim(0, 10)
			
			# Plot protocol distribution
			protocol_counts = dict(self.traffic_stats['protocol_counts'])
			if protocol_counts and len(protocol_counts) > 0:
				protocols = list(protocol_counts.keys())
				counts = list(protocol_counts.values())
				colors = ['#4FC3F7', '#66BB6A', '#BA68C8', '#FFA726', '#FF7043', '#AB47BC']
				self.ax2.bar(protocols, counts, color=colors[:len(protocols)])
				self.ax2.set_title("Protocol Distribution", color='white', fontsize=12, fontweight='bold')
				self.ax2.set_ylabel("Count", color='white', fontsize=10)
				self.ax2.set_xlabel("Protocol", color='white', fontsize=10)
				self.ax2.grid(True, alpha=0.3, color='gray')
				self.ax2.tick_params(colors='white', labelsize=9)
				# Rotate x-axis labels if needed
				if len(protocols) > 3:
					self.ax2.tick_params(axis='x', rotation=45)
			else:
				# Show empty state with sample data
				protocols = ['TCP', 'UDP', 'ICMP', 'DNS']
				counts = [10, 8, 5, 3]
				colors = ['#4FC3F7', '#66BB6A', '#BA68C8', '#FFA726']
				self.ax2.bar(protocols, counts, color=colors)
				self.ax2.set_title("Protocol Distribution (Waiting for Data)", color='white', fontsize=12, fontweight='bold')
				self.ax2.set_ylabel("Count", color='white', fontsize=10)
				self.ax2.set_xlabel("Protocol", color='white', fontsize=10)
				self.ax2.grid(True, alpha=0.3, color='gray')
				self.ax2.tick_params(colors='white', labelsize=9)
			
			# Refresh canvas with error handling
			try:
				self.canvas.draw()
			except Exception as draw_error:
				print(f"Canvas draw error: {draw_error}")
				# Try to recreate canvas if it's corrupted
				try:
					self.canvas.get_tk_widget().destroy()
					self.canvas = FigureCanvasTkAgg(self.fig, self.canvas.get_tk_widget().master)
					self.canvas.get_tk_widget().pack(fill="both", expand=True)
				except:
					pass
			
		except Exception as e:
			print(f"Graph update error: {e}")
			# Don't let graph errors crash the app
			try:
				# Show error message in graph
				self.ax1.text(0.5, 0.5, f"Graph Error: {str(e)[:50]}", 
							transform=self.ax1.transAxes, ha='center', va='center', 
							color='red', fontsize=10)
				self.canvas.draw()
			except:
				pass

	def _add_packet_to_tree(self, packet_info: dict) -> None:
		"""Add packet to treeview with limits"""
		try:
			# Limit number of packets in tree
			if len(self.packet_tree.get_children()) >= self.max_packets_in_tree:
				# Remove oldest packets
				children = self.packet_tree.get_children()
				for child in children[:100]:  # Remove 100 oldest
					self.packet_tree.delete(child)
			
			# Add new packet
			item_id = self.packet_tree.insert("", "end", values=(
				packet_info.get('time', ''),
				packet_info.get('source', ''),
				packet_info.get('destination', ''),
				packet_info.get('protocol', ''),
				packet_info.get('info', '')
			))
			
			# Store packet data for details
			self.packet_data[item_id] = packet_info
			
			# Auto-scroll to newest packet
			self.packet_tree.see(item_id)
			
		except Exception as e:
			pass

	def _on_packet_click(self, event) -> None:
		"""Handle single click on packet"""
		try:
			item = self.packet_tree.selection()[0]
			packet_info = self.packet_data.get(item, {})
			
			# Auto-pause when clicking on packets for better user experience
			if not self.is_paused and (self.sniffer is not None or self.sniffers):
				self.pause_sniffing()
			
			# Show packet details
			self.text.delete(1.0, tk.END)
			self.text.insert(tk.END, packet_info.get('details', 'No details available'))
			
		except (IndexError, KeyError):
			pass

	def _on_packet_double_click(self, event) -> None:
		"""Handle double click on packet for filtering"""
		try:
			item = self.packet_tree.selection()[0]
			packet_info = self.packet_data.get(item, {})
			
			# Show context menu for filtering options
			self._show_filter_menu(packet_info, event)
			
		except (IndexError, KeyError):
			pass

	def _show_filter_menu(self, packet_info: dict, event) -> None:
		"""Show context menu for filtering options"""
		try:
			# Create context menu
			context_menu = tk.Menu(self.root, tearoff=0)
			
			source_ip = packet_info.get('source', '')
			dest_ip = packet_info.get('destination', '')
			protocol = packet_info.get('protocol', '')
			
			if source_ip and source_ip != 'Unknown':
				context_menu.add_command(
					label=f"Filter by Source IP: {source_ip}",
					command=lambda: self._set_capture_filter(f"host {source_ip}")
				)
			
			if dest_ip and dest_ip != 'Unknown':
				context_menu.add_command(
					label=f"Filter by Destination IP: {dest_ip}",
					command=lambda: self._set_capture_filter(f"host {dest_ip}")
				)
			
			if protocol and protocol not in ['IP', 'Error']:
				context_menu.add_command(
					label=f"Filter by Protocol: {protocol}",
					command=lambda: self._set_display_filter(protocol.lower())
				)
			
			# Add port-based filters for TCP/UDP
			if protocol in ['TCP', 'UDP'] and ':' in packet_info.get('info', ''):
				info = packet_info.get('info', '')
				if '->' in info:
					parts = info.split('->')
					if len(parts) == 2:
						dest_part = parts[1].strip()
						if ':' in dest_part:
							port = dest_part.split(':')[-1]
							context_menu.add_command(
								label=f"Filter by Port: {port}",
								command=lambda: self._set_capture_filter(f"port {port}")
							)
			
			# Show menu
			context_menu.tk_popup(event.x_root, event.y_root)
			
		except Exception as e:
			pass

	def _set_capture_filter(self, filter_text: str) -> None:
		"""Set capture filter"""
		self.capture_filter_var.set(filter_text)

	def _set_display_filter(self, filter_text: str) -> None:
		"""Set display filter"""
		self.display_filter_var.set(filter_text)

	def _update_traffic_stats(self, packet_info: dict) -> None:
		"""Update traffic statistics for dashboard"""
		try:
			with self.update_lock:
				# Update packet rate
				current_time = time.time()
				if not hasattr(self, 'last_stats_update'):
					self.last_stats_update = current_time
					self.packets_this_second = 0
					self.bytes_this_second = 0
				
				# Always increment packet count
				self.packets_this_second += 1
				# Estimate bytes (rough approximation)
				self.bytes_this_second += 64  # Average packet size
				
				# Count packets per second
				if current_time - self.last_stats_update >= 1.0:
					self.traffic_stats['packets_per_second'].append(self.packets_this_second)
					self.traffic_stats['bytes_per_second'].append(self.bytes_this_second)
					self.packets_this_second = 0
					self.bytes_this_second = 0
					self.last_stats_update = current_time
				
				# Update protocol counts
				protocol = packet_info.get('protocol', 'Unknown')
				self.traffic_stats['protocol_counts'][protocol] += 1
				
				# Update top IPs
				source_ip = packet_info.get('source', 'Unknown')
				if source_ip != 'Unknown':
					self.traffic_stats['top_ips'][source_ip] += 1
				
				# Update total packet count
				self.packet_count += 1
				
				# Update UI
				self._update_dashboard_ui()
				
		except Exception as e:
			pass

	def _update_dashboard_ui(self) -> None:
		"""Update dashboard UI elements"""
		try:
			# Update statistics
			if hasattr(self, 'packets_per_sec_var'):
				current_pps = self.packets_this_second if hasattr(self, 'packets_this_second') else 0
				self.packets_per_sec_var.set(str(current_pps))
			
			if hasattr(self, 'bytes_per_sec_var'):
				current_bps = self.bytes_this_second if hasattr(self, 'bytes_this_second') else 0
				self.bytes_per_sec_var.set(f"{current_bps} B/s")
			
			if hasattr(self, 'total_packets_var'):
				self.total_packets_var.set(str(self.packet_count))
			
			# Update top protocol
			if hasattr(self, 'top_protocol_var') and self.traffic_stats['protocol_counts']:
				top_protocol = max(self.traffic_stats['protocol_counts'], key=self.traffic_stats['protocol_counts'].get)
				self.top_protocol_var.set(top_protocol)
			
			# Update top IP
			if hasattr(self, 'top_ip_var') and self.traffic_stats['top_ips']:
				top_ip = max(self.traffic_stats['top_ips'], key=self.traffic_stats['top_ips'].get)
				self.top_ip_var.set(top_ip)
			
			# Update alert count
			if hasattr(self, 'alert_count_var'):
				self.alert_count_var.set(str(len(self.alerts)))
				
		except Exception as e:
			pass

	def _detect_threats(self, packet_info: dict) -> None:
		"""Detect potential security threats"""
		try:
			source_ip = packet_info.get('source', '')
			dest_ip = packet_info.get('destination', '')
			protocol = packet_info.get('protocol', '')
			info = packet_info.get('info', '')
			
			# Port scan detection
			if protocol in ['TCP', 'UDP'] and ':' in info:
				port = info.split(':')[-1]
				if port.isdigit():
					port_num = int(port)
					key = f"{source_ip}:{dest_ip}"
					self.traffic_stats['connection_attempts'][key] += 1
					
					# Check for port scan
					if self.traffic_stats['connection_attempts'][key] > self.threat_patterns['port_scan_threshold']:
						self._create_alert("HIGH", "Port Scan Detected", 
										f"IP {source_ip} scanning {dest_ip} - {self.traffic_stats['connection_attempts'][key]} attempts")
			
			# DDoS detection
			if source_ip != 'Unknown':
				ip_key = f"ddos_{source_ip}"
				if ip_key not in self.traffic_stats:
					self.traffic_stats[ip_key] = deque(maxlen=60)
				self.traffic_stats[ip_key].append(time.time())
				
				# Check for high packet rate from single IP
				recent_packets = [t for t in self.traffic_stats[ip_key] if time.time() - t < 60]
				if len(recent_packets) > self.threat_patterns['ddos_threshold']:
					self._create_alert("CRITICAL", "DDoS Attack Detected", 
									f"IP {source_ip} sending {len(recent_packets)} packets in 60 seconds")
			
			# Suspicious port detection
			if protocol in ['TCP', 'UDP'] and ':' in info:
				port = info.split(':')[-1]
				if port.isdigit() and int(port) in self.threat_patterns['suspicious_ports']:
					self._create_alert("MEDIUM", "Suspicious Port Access", 
									f"Connection to suspicious port {port} from {source_ip}")
			
			# DNS tunneling detection (simplified)
			if protocol == 'DNS' and len(info) > 50:  # Unusually long DNS queries
				self._create_alert("LOW", "Potential DNS Tunneling", 
								f"Long DNS query from {source_ip}: {info[:50]}...")
			
		except Exception as e:
			pass

	def _create_alert(self, level: str, title: str, description: str) -> None:
		"""Create a new security alert"""
		try:
			alert = {
				'timestamp': datetime.now().strftime('%H:%M:%S'),
				'level': level,
				'title': title,
				'description': description,
				'id': hashlib.md5(f"{title}{description}{time.time()}".encode()).hexdigest()[:8]
			}
			
			# Add to alerts list
			self.alerts.append(alert)
			
			# Update alert listbox
			if hasattr(self, 'alert_listbox'):
				alert_text = f"[{alert['timestamp']}] {self.alert_levels.get(level, '❓')} {title}"
				self.alert_listbox.insert(0, alert_text)
				
				# Keep only last 100 alerts in listbox
				if self.alert_listbox.size() > 100:
					self.alert_listbox.delete(100, tk.END)
				
				# Auto-scroll to newest alert
				self.alert_listbox.see(0)
			
			# Play alert sound (if enabled)
			if self.alert_sound_enabled:
				self.root.bell()
			
			# Update status
			if level in ['HIGH', 'CRITICAL']:
				self.status_var.set(f"⚠️ {level} ALERT: {title}")
			
			# Update alert count
			self._update_dashboard_ui()
			
		except Exception as e:
			print(f"Alert creation error: {e}")
			pass

	def _clear_alerts(self) -> None:
		"""Clear all alerts"""
		try:
			self.alerts.clear()
			if hasattr(self, 'alert_listbox'):
				self.alert_listbox.delete(0, tk.END)
		except Exception as e:
			pass

	def _export_alerts(self) -> None:
		"""Export alerts to file"""
		try:
			from tkinter import filedialog
			
			filename = filedialog.asksaveasfilename(
				defaultextension=".json",
				filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
			)
			
			if filename:
				if filename.endswith('.json'):
					with open(filename, 'w') as f:
						json.dump(list(self.alerts), f, indent=2)
				else:
					with open(filename, 'w') as f:
						for alert in self.alerts:
							f.write(f"[{alert['timestamp']}] {alert['level']} - {alert['title']}: {alert['description']}\n")
				
				messagebox.showinfo("Export Complete", f"Alerts exported to {filename}")
				
		except Exception as e:
			messagebox.showerror("Export Error", f"Failed to export alerts: {e}")

	def _test_alert(self) -> None:
		"""Create a test alert for demonstration"""
		try:
			test_alerts = [
				("LOW", "Test Alert", "This is a test alert to verify the alert system is working"),
				("MEDIUM", "Suspicious Activity", "Test suspicious port access detected"),
				("HIGH", "Port Scan", "Test port scan detection from 192.168.1.100"),
				("CRITICAL", "DDoS Attack", "Test DDoS attack detected from multiple sources")
			]
			
			import random
			alert = random.choice(test_alerts)
			self._create_alert(alert[0], alert[1], alert[2])
			
		except Exception as e:
			print(f"Test alert error: {e}")

	def _apply_dark_theme(self) -> None:
		"""Apply dark theme to the application"""
		try:
			# Configure root window
			self.root.configure(bg='#1e1e1e')
			
			# Configure ttk style
			style = ttk.Style()
			
			# Set theme
			style.theme_use('clam')
			
			# Configure colors for dark theme
			style.configure('TFrame', background='#1e1e1e')
			style.configure('TLabel', background='#1e1e1e', foreground='#ffffff')
			style.configure('TButton', background='#2d2d2d', foreground='#ffffff', borderwidth=1)
			style.map('TButton', background=[('active', '#404040'), ('pressed', '#1a1a1a')])
			
			# Configure Combobox
			style.configure('TCombobox', background='#2d2d2d', foreground='#ffffff', fieldbackground='#2d2d2d')
			style.map('TCombobox', fieldbackground=[('readonly', '#2d2d2d')])
			
			# Configure Entry
			style.configure('TEntry', background='#2d2d2d', foreground='#ffffff', fieldbackground='#2d2d2d')
			
			# Configure Notebook
			style.configure('TNotebook', background='#1e1e1e', tabmargins=[2, 5, 2, 0])
			style.configure('TNotebook.Tab', background='#2d2d2d', foreground='#ffffff', padding=[10, 5])
			style.map('TNotebook.Tab', background=[('selected', '#404040'), ('active', '#353535')])
			
			# Configure LabelFrame
			style.configure('TLabelframe', background='#1e1e1e', foreground='#ffffff')
			style.configure('TLabelframe.Label', background='#1e1e1e', foreground='#ffffff')
			
			# Configure Treeview
			style.configure('Treeview', background='#2d2d2d', foreground='#ffffff', fieldbackground='#2d2d2d')
			style.configure('Treeview.Heading', background='#404040', foreground='#ffffff')
			style.map('Treeview', background=[('selected', '#404040')])
			
			# Configure Scrollbar
			style.configure('TScrollbar', background='#2d2d2d', troughcolor='#1e1e1e', borderwidth=0, arrowcolor='#ffffff')
			style.map('TScrollbar', background=[('active', '#404040')])
			
			# Update text widget colors
			self._update_text_widgets()
			
		except Exception as e:
			print(f"Theme application error: {e}")

	def _update_text_widgets(self) -> None:
		"""Update text widget colors for dark theme"""
		try:
			# Main packet text area
			if hasattr(self, 'text'):
				self.text.configure(
					bg='#0b0e11', 
					fg='#e6edf3', 
					insertbackground='#e6edf3',
					selectbackground='#404040',
					selectforeground='#ffffff'
				)
			
			# Browser activity text
			if hasattr(self, 'browser_text'):
				self.browser_text.configure(
					bg='#1e1e1e', 
					fg='#e6edf3', 
					insertbackground='#e6edf3',
					selectbackground='#404040',
					selectforeground='#ffffff'
				)
			
			# Alert listbox
			if hasattr(self, 'alert_listbox'):
				self.alert_listbox.configure(
					bg='#2d2d2d',
					fg='#ffffff',
					selectbackground='#404040',
					selectforeground='#ffffff'
				)
			
		except Exception as e:
			print(f"Text widget update error: {e}")


def main() -> int:
	"""Main function with administrator privilege checking"""
	print("🌐 Network Packet Sniffer")
	print("=" * 40)
	
	# Check for existing instance
	lock_file = os.path.join(os.path.dirname(__file__), "sniffer.lock")
	if os.path.exists(lock_file):
		# Check if the process is actually running
		try:
			with open(lock_file, 'r') as f:
				pid = int(f.read().strip())
			# Check if process exists (Windows)
			import subprocess
			result = subprocess.run(['tasklist', '/FI', f'PID eq {pid}'], 
								  capture_output=True, text=True)
			if str(pid) not in result.stdout:
				# Process doesn't exist, remove stale lock file
				os.remove(lock_file)
				print("🔄 Removed stale lock file")
			else:
				print("⚠️  Another instance is already running!")
				print("   Please close the existing window first.")
				input("Press Enter to exit...")
				return 1
		except:
			# Lock file is corrupted, remove it
			os.remove(lock_file)
			print("🔄 Removed corrupted lock file")
	
	# Create lock file
	try:
		with open(lock_file, 'w') as f:
			f.write(str(os.getpid()))
	except:
		pass
	
	# Check administrator privileges
	if not is_admin():
		print("⚠️  WARNING: Not running as Administrator")
		print("   Packet capture may not work properly")
		print("   For full functionality, run as Administrator")
		print()
		
		# Ask user if they want to restart as admin
		response = input("Do you want to restart as Administrator? (y/n): ").lower().strip()
		if response in ['y', 'yes']:
			run_as_admin()  # This will exit the current instance
		else:
			print("Continuing with limited functionality...")
			print()
	
	# Create and configure the main window
	root = tk.Tk()
	root.title("Network Monitoring")
	root.geometry("1200x800")
	root.minsize(800, 600)
	
	# Set window icon (if available)
	try:
		root.iconbitmap("icon.ico")
	except:
		pass
	
	# Configure high DPI scaling
	try:
		root.call("tk", "scaling", 1.25)
	except Exception:
		pass
	
	# Create and run the application
	app = PacketSnifferGUI(root)
	
	print("✅ Application started successfully!")
	print("📋 Instructions:")
	print("   1. Click 'Start Monitoring' to begin")
	print("   2. Select a network interface")
	print("   3. Browse websites to see activity")
	print("   4. Check 'Browser Activity' tab")
	print()
	
	# Add cleanup function for lock file
	def cleanup():
		try:
			if os.path.exists(lock_file):
				os.remove(lock_file)
		except:
			pass
	
	# Register cleanup function
	root.protocol("WM_DELETE_WINDOW", lambda: [cleanup(), root.destroy()])
	
	try:
		root.mainloop()
	finally:
		cleanup()
	
	return 0


if __name__ == "__main__":
	sys.exit(main())


