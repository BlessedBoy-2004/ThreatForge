import psutil
from scapy.all import sniff, DNSQR
from typing import List, Dict

class BehaviorMonitor:
    """Detect suspicious system activities"""
    
    LOLBINS = ["mshta.exe", "rundll32.exe", "wmic.exe"]
    
    def check_lolbins(self) -> List[Dict]:
        """Find Living-Off-The-Land binary usage"""
        alerts = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            if proc.info['name'] in self.LOLBINS:
                alerts.append({
                    'pid': proc.info['pid'],
                    'process': proc.info['name'],
                    'path': proc.info['exe']
                })
        return alerts
    
    def detect_dns_tunneling(self) -> None:
        """Monitor DNS traffic for exfiltration"""
        def packet_callback(packet):
            if packet.haslayer(DNSQR):
                query = packet[DNSQR].qname.decode()
                if len(query) > 50 or '.exe' in query:
                    print(f"🚨 DNS Tunneling Detected: {query}")
        
        sniff(filter="udp port 53", prn=packet_callback, store=0)

if __name__ == "__main__":
    monitor = BehaviorMonitor()
    print("🔍 Checking for LOLBin usage...")
    print(monitor.check_lolbins())
