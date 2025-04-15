
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

        # Here you initialize hosts, web servers and switches
        # (There are sample host, switch and link initialization,  you can rewrite it in a way you prefer)
        ### UPDATE THIS PART AS YOU SEE FIT ###
        # This is a simple implementation of a simple networl
        # # Initialize hosts
        # h1 = self.addHost('h1', ip='100.0.0.10/24')
        # h2 = self.addHost('h2', ip='100.0.0.11/24')

        # # Initial switches
        # sw1 = self.addSwitch('sw1', dpid="1")

        # # Defining links
        # self.addLink(h1, sw1)
        # self.addLink(h2, sw1)

        # This is the implementation of the topology for the project
        # Please update the IP addresses to the correct ones
        # You can update the topology as you see fit

        # Initialize hosts for user zone
        h1 = self.addHost('h1', ip='10.0.0.50/24')
        h2 = self.addHost('h2', ip='10.0.0.51/24')
        # Initialize switch for user zone
        s1 = self.addSwitch('s1', dpid="1")
        # Connect hosts to switch
        self.addLink(h1, s1)
        self.addLink(h2, s1)

        # Initialize napt between user zone and inferencing zone
        napt = self.addSwitch('napt', dpid="4") # dpid is 4 because we have 3 normal switches in the topology
        # Connect user zone switch to napt
        self.addLink(s1, napt)

        # Initalize access switch for inferencing zone
        s2 = self.addSwitch('s2', dpid="2")
        # Connect napt to access switch
        self.addLink(napt, s2)

        # Initialize ids switch for inferencing zone
        ids = self.addSwitch('ids', dpid="5") # dpid is 5 because we have 3 normal switches and 1 napt switch in the topology
        # Connect access switch to ids switch
        self.addLink(s2, ids)

        # Create inspection server for inferencing zone
        # TODO: Change IP to correct IP
        insp = self.addHost('insp', ip='10.0.0.30/24')
        # insp = self.addHost('insp', ip='100.0.0.30/24')
        
        # Connect inspection server to ids switch
        self.addLink(insp, ids)

        # Create load balancer for inferencing zone
        lb1 = self.addSwitch('lb1', dpid="6")
        # Connect ids switch to load balancer
        self.addLink(ids, lb1)

        # Create switch to connect load balancer to inferencing servers
        s3 = self.addSwitch('s3', dpid="3")
        # Connect load balancer to switch
        self.addLink(lb1, s3)

        # Create inferencing servers 
        # TODO: Change IPs to correct IPs
        llm1 = self.addHost('llm1', ip='10.0.0.40/24')
        llm2 = self.addHost('llm2', ip='10.0.0.41/24')
        llm3 = self.addHost('llm3', ip='10.0.0.42/24')

        # llm1 = self.addHost('llm1', ip='100.0.0.40/24')
        # llm2 = self.addHost('llm2', ip='100.0.0.41/24')
        # llm3 = self.addHost('llm3', ip='100.0.0.42/24')

        # Connect inferencing servers to switch
        self.addLink(llm1, s3)
        self.addLink(llm2, s3)
        self.addLink(llm3, s3)

def startup_services(net):
    # Start http services and executing commands you require on each host...
    ### COMPLETE THIS PART ###
    pass



# topos = {'mytopo': (lambda: MyTopo())}

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

    startup_services(net)
    # Start the network
    net.start()

    # Start the CLI
    CLI(net)

    # You may need some commands before stopping the network! If you don't, leave it empty
    ### COMPLETE THIS PART ###
    net.stop()
