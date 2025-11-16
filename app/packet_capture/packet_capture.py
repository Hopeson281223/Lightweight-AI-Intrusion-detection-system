import threading
import time
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP
from scapy.packet import Packet
import requests
import json
import platform
from datetime import datetime
import numpy as np
import sqlite3
from app.ml.preprocess import LIVE_FEATURES
from app.storage.db import get_db, create_session, end_session  

class LivePacketCapture:
    def __init__(self, model_endpoint="http://localhost:8000/predict"):
        self.model_endpoint = model_endpoint
        self.capture_thread = None
        self.is_capturing = False
        self.packet_count = 0
        self.current_interface = r"\Device\NPF_{662136C5-DAF0-45FA-AFF8-1889200C99C2}"
        self.last_error = None
        self.current_model = "random_forest"
        # For session tracking
        self.session_id = None
        self.session_start_time = None
        self.prediction_count = 0
        self.alert_count = 0

        # For storing live logs
        self.session_logs = []  
        
        # Flow tracking
        self.flows = defaultdict(lambda: {
            "timestamps": deque(),
            "fwd_lengths": deque(),
            "bwd_lengths": deque(),
            "fwd_flags": defaultdict(int),
            "bwd_flags": defaultdict(int),
            "fwd_headers": deque(),
            "bwd_headers": deque(),
            "init_win_fwd": None,
            "init_win_bwd": None,
            "act_data_pkt_fwd": 0
        })
        self.MAX_FLOW_AGE = 5 

        # Add stop event for forceful termination
        self.stop_event = threading.Event()

    def list_available_interfaces(self):
        """Return all usable network interfaces with proper active status."""
        try:
            from scapy.arch.windows import get_windows_if_list
            import psutil
            
            win_ifs = get_windows_if_list()
            interfaces = []

            # Get network I/O statistics to find truly active interfaces
            net_io = psutil.net_io_counters(pernic=True)
            
            for iface in win_ifs:
                desc = iface.get("description", "").lower()
                name = iface.get("name", "Unknown")
                guid = iface.get("guid", "")

                # Exclude virtual and filter drivers more precisely
                exclude_keywords = ["filter", "scheduler", "miniport", "direct", "virtualbox", "vmware", "vpn", "tap"]
                if any(bad in desc for bad in exclude_keywords):
                    continue

                # Check if interface is active (has recent traffic)
                is_active = False
                bytes_sent = 0
                bytes_recv = 0
                
                try:
                    if name in net_io:
                        stats = net_io[name]
                        bytes_sent = stats.bytes_sent
                        bytes_recv = stats.bytes_recv
                        # Consider interface active if it has any traffic or is the default route
                        is_active = (bytes_sent > 0 or bytes_recv > 0)
                except Exception:
                    pass

                # Also check if interface is up
                try:
                    iface_stats = psutil.net_if_stats().get(name)
                    if iface_stats and iface_stats.isup:
                        is_active = True  # Mark as active if interface is up
                except Exception:
                    pass

                interfaces.append({
                    "name": name,
                    "description": iface.get("description", ""),
                    "device": f"\\Device\\NPF_{guid}",
                    "active": is_active,
                    "bytes_sent": bytes_sent,
                    "bytes_recv": bytes_recv
                })

            if not interfaces:
                interfaces = [{"name": "No valid interfaces found", "device": "none", "active": False}]

            # Sort active interfaces first, then by name
            interfaces.sort(key=lambda x: (-x["active"], x["name"].lower()))
            return interfaces

        except Exception as e:
            print(f"Interface listing error: {e}")
            return [{"name": "Error listing interfaces", "device": "none", "active": False}]
        
    def set_interface(self, interface_name):
        if not self.is_capturing:
            self.current_interface = interface_name
            print(f"Interface set to: {interface_name}")
            return True
        self.last_error = "Cannot change interface while capturing"
        return False
   
    def extract_flow_features(self, flow, dst_port):
        """Extract features from completed flow"""
        try:
            fwd = np.array(flow["fwd_lengths"]) if flow["fwd_lengths"] else np.array([0])
            bwd = np.array(flow["bwd_lengths"]) if flow["bwd_lengths"] else np.array([0])
            ts = np.array(flow["timestamps"]) if flow["timestamps"] else np.array([0])
            fwd_hdr = np.array(flow["fwd_headers"]) if flow["fwd_headers"] else np.array([0])
            bwd_hdr = np.array(flow["bwd_headers"]) if flow["bwd_headers"] else np.array([0])

            total_bytes = fwd.sum() + bwd.sum()
            duration = ts[-1] - ts[0] if len(ts) > 1 else 0
            flow_bytes_s = total_bytes / (duration + 1e-6)
            flow_pkts_s = (len(fwd) + len(bwd)) / (duration + 1e-6)
            iat = np.diff(ts) if len(ts) > 1 else np.array([0])
            down_up_ratio = bwd.sum() / (fwd.sum() + 1e-6)

            features = [
                dst_port, duration, len(fwd), len(bwd), fwd.sum(), bwd.sum(),
                fwd.max(), fwd.min(), fwd.mean(), fwd.std(),
                bwd.max(), bwd.min(), bwd.mean(), bwd.std(),
                flow_bytes_s, flow_pkts_s, iat.mean(), iat.std(), iat.max(), iat.min(),
                flow["fwd_flags"]["PSH"], flow["bwd_flags"]["PSH"],
                flow["fwd_flags"]["URG"], flow["bwd_flags"]["URG"],
                flow["fwd_flags"]["FIN"], flow["fwd_flags"]["SYN"], flow["fwd_flags"]["RST"],
                flow["fwd_flags"]["PSH"] + flow["bwd_flags"]["PSH"],
                flow["fwd_flags"]["ACK"] + flow["bwd_flags"]["ACK"],
                flow["fwd_flags"]["URG"] + flow["bwd_flags"]["URG"],
                flow["fwd_flags"].get("CWE", 0) + flow["bwd_flags"].get("CWE", 0),
                flow["fwd_flags"].get("ECE", 0) + flow["bwd_flags"].get("ECE", 0),
                (fwd.sum() + bwd.sum()) / (len(fwd) + len(bwd) + 1e-6),
                fwd_hdr.mean(), bwd_hdr.mean(),
                fwd.min(), fwd.max(),
                np.mean(np.concatenate([fwd, bwd])),
                np.std(np.concatenate([fwd, bwd])),
                np.var(np.concatenate([fwd, bwd])),
                down_up_ratio,
                len(fwd), len(bwd),
                flow["init_win_fwd"] or 0,
                flow["init_win_bwd"] or 0,
                flow["act_data_pkt_fwd"]
            ]
            return [float(x) for x in features]
        except Exception as e:
            print(f"Flow feature extraction error: {e}")
            return None
    
    def flush_old_flows(self):
        """Flush completed flows for analysis"""
        now = time.time()
        to_delete = []
        
        # First collects all flows to process
        for key, flow in list(self.flows.items()):  # Uses list() to avoid modification during iteration
            if flow["timestamps"] and now - flow["timestamps"][-1] > self.MAX_FLOW_AGE:
                to_delete.append((key, flow.copy()))  # Stores a copy of the flow data
        
        # Then processes and deletes them
        for key, flow_data in to_delete:
            if key not in self.flows:
                continue

            features = self.extract_flow_features(flow_data, key[3])
            src, dst = key[0], key[1]

            if features:
                print(f"Flow completed: {src} -> {dst}:{key[3]} (Packets: {len(flow_data['timestamps'])})")

                # Save to database
                packet_id = self.save_flow_to_database(key, flow_data, features)
                if packet_id:
                    self.send_prediction(features, packet_id, key)

            if key in self.flows:
                del self.flows[key]
    
    def save_flow_to_database(self, flow_key, flow_data, features):
        """Save flow to database using your existing db connection"""
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            # Insert flow as packet with session_id
            cursor.execute("""
                INSERT INTO packets (ts, src_ip, dst_ip, src_port, dst_port, protocol, length, features_json, session_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                flow_key[0],  # src_ip
                flow_key[1],  # dst_ip
                flow_key[2],  # src_port
                flow_key[3],  # dst_port
                flow_key[4],  # protocol
                sum(flow_data["fwd_lengths"]) + sum(flow_data["bwd_lengths"]),  # total length
                json.dumps(features),
                self.session_id  # session_id
            ))
            packet_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            print(f"Saved flow as packet {packet_id} in session {self.session_id}")
            return packet_id
            
        except Exception as e:
            print(f"Database error: {e}")
            return None
    
    def send_prediction(self, features, packet_id, flow_key):
        """Send features for ML prediction"""
        try:
            src_ip, dst_ip, src_port, dst_port, protocol = flow_key
            response = requests.post(
                self.model_endpoint,
                json={
                    "dataset": "cic",
                    "features": features,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "model_type": self.current_model  
                },
                timeout=3
            )
            if response.status_code == 200:
                result = response.json()
                
                # Save prediction
                conn = get_db()
                cursor = conn.cursor()
                
                # Use local time for prediction timestamp
                local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute(
                    "INSERT INTO predictions (packet_id, label, score, session_id, created_at) VALUES (?, ?, ?, ?, ?)",
                    (packet_id, result["label"], result["confidence"], self.session_id, local_time)
                )
                prediction_id = cursor.lastrowid
                self.prediction_count += 1
                
                # Create alert if anomalous
                if result["label"] == "ANOMALOUS" and result["confidence"] > 0.7:
                    # Use local time for alert timestamp
                    cursor.execute(
                        "INSERT INTO alerts (prediction_id, severity, message, session_id, created_at) VALUES (?, ?, ?, ?, ?)",
                        (prediction_id, "HIGH", f"Anomalous traffic from {src_ip} to {dst_ip} (conf: {result['confidence']:.2f})", self.session_id, local_time)
                    )
                    self.alert_count += 1
                    print(f"ALERT: Anomalous traffic detected at {local_time}!")
                
                conn.commit()
                conn.close()
                
                # Add to session logs with local time 
                log_entry = {
                    "timestamp": local_time,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "label": result["label"],
                    "confidence": result["confidence"],
                    "message": f"Prediction: {result['label']} (conf: {result['confidence']:.2f})",
                    "model_type": self.current_model  
                }
                self.session_logs.append(log_entry)
                
                # FIX: Show which model was used in the log
                model_abbr = "RF" if self.current_model == "random_forest" else "DT"
                print(f"{src_ip} → {dst_ip} | {protocol} | {result['label']} (conf: {result['confidence']:.2f}) [{model_abbr}]")
                    
        except Exception as e:
            print(f"Prediction error: {e}")
                                
    def packet_handler(self, packet):
        """Process each packet and add to flows"""
        try:
            self.packet_count += 1
            
            if not packet.haslayer(IP):
                return

            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
            if proto == "OTHER":
                return

            src, dst = packet[IP].src, packet[IP].dst
            sport, dport = getattr(packet, "sport", 0), getattr(packet, "dport", 0)
            key = (src, dst, sport, dport, proto)
            rev_key = (dst, src, dport, sport, proto)
            now = time.time()

            if TCP in packet:
                flags = packet[TCP].flags
                self.flows[key]["init_win_fwd"] = self.flows[key]["init_win_fwd"] or packet[TCP].window
                self.flows[rev_key]["init_win_bwd"] = self.flows[rev_key]["init_win_bwd"] or packet[TCP].window
                self.flows[key]["act_data_pkt_fwd"] += 1
                self.flows[key]["fwd_flags"]["SYN"] += int(flags & 0x02 != 0)
                self.flows[key]["fwd_flags"]["ACK"] += int(flags & 0x10 != 0)
                self.flows[key]["fwd_flags"]["FIN"] += int(flags & 0x01 != 0)
                self.flows[key]["fwd_flags"]["PSH"] += int(flags & 0x08 != 0)
                self.flows[key]["fwd_flags"]["URG"] += int(flags & 0x20 != 0)
                self.flows[key]["fwd_flags"]["ECE"] += int(flags & 0x40 != 0)
                self.flows[key]["fwd_flags"]["CWE"] += int(flags & 0x80 != 0)

            pkt_len = len(packet)
            header_len = packet[IP].ihl * 4 + (packet[TCP].dataofs * 4 if TCP in packet else 0)
            self.flows[key]["timestamps"].append(now)
            self.flows[key]["fwd_lengths"].append(pkt_len)
            self.flows[key]["fwd_headers"].append(header_len)

            # Show live packet info
            print(f"Packet #{self.packet_count}: {src} -> {dst}:{dport}")
            
            # Flush old flows periodically
            if self.packet_count % 10 == 0:
                self.flush_old_flows()
                    
        except Exception as e:
            print(f"Packet handler error: {e}")
    
    def start_capture(self, interface=None, model_type="random_forest"):
        if self.is_capturing:
            self.last_error = "Capture already running"
            return False

        self.current_model = model_type  

        # Auto-select first active interface if none provided
        if not interface or interface == "auto":
            interfaces = self.list_available_interfaces()
            active_ifs = [i for i in interfaces if i.get("active")]
            if active_ifs:
                self.current_interface = active_ifs[0]["device"]
                print(f"Auto-selected active interface: {active_ifs[0]['name']}")
            else:
                self.last_error = "No active interface found"
                print("No active interface found for capture.")
                return False
        else:
            self.current_interface = interface

        # Create new session
        self.session_id = f"session_{int(time.time())}_{self.packet_count}"
        self.session_start_time = datetime.now().isoformat()
        self.prediction_count = 0
        self.alert_count = 0
        self.session_logs = []  # Reset logs for new session
        
        # Create session in database with start time AND model
        if create_session(self.session_id, self.current_interface, self.session_start_time, self.current_model):
            print(f"New capture session started: {self.session_id} at {self.session_start_time} with model: {self.current_model}")
        else:
            print("Could not create session in database, but capture will continue")
        
        self.is_capturing = True
        self.packet_count = 0
        self.flows.clear()
        self.last_error = None

        # Launch capture in background thread - MAKE SURE METHOD NAME IS CORRECT
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)  # Use correct method name
        self.capture_thread.start()

        print(f"Flow-based packet capture started on {self.current_interface} using {self.current_model}")
        return True
    
    def stop_capture(self):
        print(f"stop_capture called - is_capturing: {self.is_capturing}, session_id: {self.session_id}")
        
        if not self.is_capturing:
            self.last_error = "No capture running"
            print(f"Stop failed: {self.last_error}")
            return False
            
        print("Stopping capture immediately...")
        
        try:
            # Set capturing to False immediately
            self.is_capturing = False
            self.last_error = None
            
            # Store session data for later processing
            final_session_id = self.session_id
            final_packet_count = self.packet_count
            final_prediction_count = self.prediction_count
            final_alert_count = self.alert_count
            final_logs = self.session_logs.copy()
            
            print(f"Session data saved: {final_session_id} with {final_packet_count} packets")
            
            # Don't flush old flows here - it takes too long and continues processing
            # Instead, just clear the flows without processing them
            print("Clearing flows without processing...")
            flows_count = len(self.flows)
            self.flows.clear()
            print(f"Cleared {flows_count} flows")
            
            # Save session to database (this is fast)
            print("Saving session to database...")
            from app.storage.db import end_session
            success = end_session(final_session_id, final_packet_count, final_prediction_count, final_alert_count, final_logs)
            if success:
                print(f"Session {final_session_id} saved to database")
            else:
                print("Could not save session to database")
            
            # Stop the capture thread with timeout
            if self.capture_thread and self.capture_thread.is_alive():
                print("Stopping capture thread...")
                self.capture_thread.join(timeout=1.0)
                if self.capture_thread.is_alive():
                    print("Capture thread still running, but returning success")
                else:
                    print("Capture thread stopped")
            
            print(f"Capture stopped completely. Packets: {final_packet_count}, Predictions: {final_prediction_count}")
            return True
            
        except Exception as e:
            print(f"ERROR in stop_capture: {e}")
            import traceback
            traceback.print_exc()
            self.last_error = str(e)
            return False
    
    def _capture_loop(self):
        """Main capture loop"""
        print(f"Starting FLOW-BASED capture on {self.current_interface}")
        try:
            sniff(
                iface=self.current_interface,
                prn=self.packet_handler,
                store=False,
                filter="ip",
                stop_filter=lambda x: not self.is_capturing
            )
        except Exception as e:
            print(f"Capture error: {e}")
        finally:
            print("Capture loop ended")
            
    def get_status(self):
        return {
            "is_capturing": self.is_capturing,
            "packets_captured": self.packet_count,
            "active_flows": len(self.flows),
            "interface": self.current_interface,
            "session_id": self.session_id,
            "predictions_count": self.prediction_count,
            "alerts_count": self.alert_count,
            "logs_count": len(self.session_logs),
            "current_model": self.current_model 
        }

packet_capture = LivePacketCapture()