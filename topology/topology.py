from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController, OVSController, Controller
from mininet.node import OVSSwitch
import subprocess
import signal
import os
import time

class MyTopo(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)
        
        # Initialize hosts for user zone
        h1 = self.addHost('h1', ip='10.0.0.50/24')
        h2 = self.addHost('h2', ip='10.0.0.51/24')
        
        #MAC address for hosts
        for host in [h1, h2]:
            host.cmd('arp -s 100.0.0.45 00:00:00:00:00:45')
        
        # Initialize switch for user zone
        sw1 = self.addSwitch('sw1', dpid="1")
        
        # Connect hosts to switch
        self.addLink(h1, sw1)
        self.addLink(h2, sw1)
        
        # Initialize napt between user zone and inferencing zone
        napt = self.addSwitch('napt', dpid="4", ip='10.0.0.1/24')  # User zone interface
        self.addSwitch('napt', dpid="4", ip='100.0.0.1/24')        # Inferencing zone interface        

        # Connect user zone switch to napt
        self.addLink(sw1, napt)
        
        # Initialize core switch for inferencing zone
        sw2 = self.addSwitch('sw2', dpid="2")
        
        # Connect napt to core switch
        self.addLink(napt, sw2)
        
        # Initialize ids switch for inferencing zone
        ids = self.addSwitch('ids', dpid="5")
        
        # Connect core switch to ids switch
        self.addLink(sw2, ids)
        
        # Create inspection server for inferencing zone
        insp = self.addHost('insp', ip='100.0.0.30/24')
        
        # Connect inspection server to ids switch
        self.addLink(insp, ids)
        
        # Create load balancer for inferencing zone
        lb1 = self.addSwitch('lb1', dpid="6")
        
        # Connect ids switch to load balancer
        self.addLink(ids, lb1)
        
        # Create switch to connect load balancer to inferencing servers
        sw3 = self.addSwitch('sw3', dpid="3")
        
        # Connect load balancer to switch
        self.addLink(lb1, sw3)
        
        # Create inferencing servers
        llm1 = self.addHost('llm1', ip='100.0.0.40/24')
        llm2 = self.addHost('llm2', ip='100.0.0.41/24')
        llm3 = self.addHost('llm3', ip='100.0.0.42/24')
        
        # Connect inferencing servers to switch
        self.addLink(llm1, sw3)
        self.addLink(llm2, sw3)
        self.addLink(llm3, sw3)

def startup_services(net):
    # Start HTTP services on the inferencing servers
    print("Starting HTTP services on inferencing servers...")
    for i in range(1, 4):
        server = net.get(f'llm{i}')
        
        # Create a directory for HTTP files
        server.cmd('mkdir -p /home/mininet/web')
        
        # Create test HTML files (3-5 files as required)
        for j in range(1, 6):  # Creating 5 test pages
            server.cmd(f'echo "<html><body><h1>Test Page {j} from LLM Server {i}</h1></body></html>" > /home/mininet/web/page{j}.html')
        
        # Create an index.html file
        server.cmd(f'echo "<html><body><h1>LLM Server {i}</h1><ul>' + 
                   ''.join([f'<li><a href=\\"page{j}.html\\">Test Page {j}</a></li>' for j in range(1, 6)]) + 
                   '</ul></body></html>" > /home/mininet/web/index.html')
        
        # Start a simple HTTP server on port 80 as mentioned in the project description
        server.cmd('cd /home/mininet/web && python3 -m http.server 80 &')
        
    print("HTTP services started")

    # Set up packet capture on the inspector server
    insp = net.get('insp')
    insp.cmd('tcpdump -i insp-eth0 -w /tmp/inspector_capture.pcap &')
    print("Packet capture started on inspector server")

    # Set the default routes
    print("Setting up default routes...")
    
    # Set default routes for hosts in the user zone
    h1 = net.get('h1')
    h2 = net.get('h2')
    h1.cmd('ip route add default via 10.0.0.1')
    h2.cmd('ip route add default via 10.0.0.1')

    # Add default route for NAPT
    napt.cmd('ip route add default via 100.0.0.1')
    
    # Set default routes for inferencing servers
    llm1 = net.get('llm1')
    llm2 = net.get('llm2')
    llm3 = net.get('llm3')
    llm1.cmd('ip route add default via 100.0.0.1')
    llm2.cmd('ip route add default via 100.0.0.1')
    llm3.cmd('ip route add default via 100.0.0.1')
    
    # Set default route for inspector server
    insp.cmd('ip route add default via 100.0.0.1')
    
    print("Default routes set up")

if __name__ == "__main__":
    # Create topology
    topo = MyTopo()
    
    ctrl = RemoteController("c0", ip="127.0.0.1", port=6633)
    
    # Create the network
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=ctrl,
                  autoSetMacs=True,
                  autoStaticArp=True,
                  build=True,
                  cleanup=True)
    
    # Start the network
    net.start()
    
    # Start services
    startup_services(net)
    
    # Start the CLI
    CLI(net)
    
    # Clean up before stopping the network
    print("Cleaning up...")
    
    # Stop HTTP servers
    for i in range(1, 4):
        server = net.get(f'llm{i}')
        server.cmd('pkill -f "python3 -m http.server"')
    
    # Stop packet capture on inspector
    insp = net.get('insp')
    insp.cmd('pkill tcpdump')
    
    net.stop()
