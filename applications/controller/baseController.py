from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt
from forwarding.l2_learning import LearningSwitch
import subprocess
import shlex
import datetime
import click_wrapper

log = core.getLogger()


class controller (object):
    # Here you should save a reference to each element:
    devices = dict()

    # Here you should save a reference to the place you saw the first time a specific source mac
    firstSeenAt = dict()

    def __init__(self):

        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        
        """
        This function is called everytime a new device starts in the network.
        You need to determine what is the new device and run the correct application based on that.
        
        Note that for normal switches you should use l2_learning module that already is available in pox as an external module.
        """

        # In this phase, you will need to run your network functions on the controller. Here is just an example how you can do it:
        # click = click_wrapper.start_click("../nfv/forwarder.click", "", "/tmp/forwarder.stdout", "/tmp/forwarder.stderr")

        # You might need a record of switches that are already connected to the controller. 
        # Please keep them in "devices".
        # For instance: self.devices[len(self.devices)] = mySwitch
        id = event.dpid
        if(id<=3):
            # This is a normal learning switch
            # You should run the l2_learning module
            log.info(f"Starting Learning Switch for switch {id}")
            self.devices[id] = LearningSwitch(event.connection, False)
        elif(id==4):
            # This is the NAPT switch
            # You should run the NAPT module click node (/TODO Replace napt.click with your NAPT implementation)
            log.info("Starting NAPT")
            self.devices[id] = click_wrapper.start_click("/opt/pox/ext/napt.click", "", "/tmp/napt.stdout", "/tmp/napt.stderr")
        elif(id==5):
            # This is the IDS switch
            # You should run the IDS module click node (/TODO Replace ids.click with your ids implementation)
            log.info("Starting IDS")
            self.devices[id] = click_wrapper.start_click("/opt/pox/ext/ids.click", "", "/tmp/ids.stdout", "/tmp/ids.stderr")
        elif(id==6):
            # This is the Load Balancer switch
            # You should run the Load Balancer module click node (/TODO Replace lb1.click with your load balancer implementation)
            log.info("Starting Load Balancer")
            self.devices[id] = click_wrapper.start_click("/opt/pox/ext/lb1.click", "", "/tmp/lb1.stdout", "/tmp/lb1.stderr")
        else:
            # Error
            log.error("Unknown device connected to the controller")

        return

    # This should be called by each element in your application when a new source MAC is seen

    def updatefirstSeenAt(self, mac, where):
       
        """
        This function updates your first seen dictionary with the given input.
        It should be called by each element in your application when a new source MAC is seen
        """
       
        # TODO: More logic needed here!
        # self.firstSeenAt[mac] = (where, datetime.datetime.now().isoformat())
        if mac not in self.firstSeenAt:
            log.info(f"New MAC {mac} seen at {where}")
            self.firstSeenAt[mac] = (where, datetime.datetime.now().isoformat())
        else:
            log.info(f"MAC {mac} is already in the firstSeenAt dictionary")




def launch(configuration=""):
    core.registerNew(controller)
