from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from topology import *
import testing
import sys

topos = {'mytopo': (lambda: MyTopo())}


def run_tests(net):

    # Grab the hosts from the net
    h1 = net.get('h1')
    h2 = net.get('h2')

    all_ok = True       # Track overall success

    # --- 1) NAPT tests ---

    # Ensure both hosts can reach the NAT gateway at 10.0.0.1
    print("==> Testing NAPT gateway ping from h1 and h2")
    if testing.ping(h1, '10.0.0.1', expected=True):
        print("  [OK] NAPT gateway ping from h1")
    else:
        print("  [FAIL] NAPT gateway ping from h1")
        all_ok = False
    if testing.ping(h2, '10.0.0.1', expected=True):
        print("  [OK] NAPT gateway ping from h2")
    else:
        print("  [FAIL] NAPT gateway ping from h2")
        all_ok = False

    # Test outbound ICMP: h1 → server llm1 via source-NAT
    print("==> Testing h1 → llm1 (100.0.0.40) through NAPT")
    if testing.ping(h1, '100.0.0.40', expected=True):
        print("  [OK] ICMP outbound via SNAT → llm1 (h1)")
    else:
        print("  [FAIL] ICMP outbound failed for h1")
        all_ok = False

    # Test outbound ICMP: h2 → server llm2 via source-NAT
    print("==> Testing h2 → llm2 (100.0.0.41) through NAPT")
    if testing.ping(h2, '100.0.0.41', expected=True):
        print("  [OK] ICMP outbound via SNAT → llm2 (h2)")
    else:
        print("  [FAIL] ICMP outbound failed for h2")
        all_ok = False

    # Test inbound to private IP: llm1 → h1 should be blocked (no direct route)
    print("==> Testing inbound llm1 → h1 (10.0.0.50) should be blocked")
    if testing.ping(net.get('llm1'), '10.0.0.50', expected=False):
        print("  [OK] inbound to private IP is blocked")
    else:
        print("  [FAIL] private‐IP reachability unexpected")
        all_ok = False

    # Test ping to an unused private IP (10.0.0.99) should fail
    print("==> Testing ping to unused 10.0.0.99 (should fail)")
    if testing.ping(h1, '10.0.0.99', expected=False):
        print("  [OK] unused private IP dropped")
    else:
        print("  [FAIL] unexpected reply from .99")
        all_ok = False



    # --- 2) Load-Balancer tests ---

    VIP = '100.0.0.45' # Virtual service IP handled by lb1

    # ARP test: hosts should ARP-resolve the VIP
    print("==> Testing LB ARP for VIP")
    if testing.ping(h1, VIP, expected=True):
        print("  [OK] h1 ARPed VIP")
    else:
        print("  [FAIL] h1 ARPed VIP")
        all_ok = False

    # HTTP GET test: VIP:80 should return 200 from one of the servers
    print("==> Testing HTTP GET → VIP")
    if testing.curl(h1, VIP, method='GET', expected=True):
        print("  [OK] HTTP GET through LB")
    else:
        print("  [FAIL] HTTP GET through LB")
        all_ok = False



    # --- 3) IDS tests ---

    # Safe POST should pass through IDS and reach LB
    print("==> Testing IDS allows POST")
    if testing.curl(h1, VIP, method='POST', payload='hello', expected=True):
        print("  [OK] POST passed IDS → LB")
    else:
        print("  [FAIL] POST blocked by IDS")
        all_ok = False

    # TRACE method should be blocked by IDS
    print("==> Testing IDS blocks TRACE")
    if testing.curl(h1, VIP, method='TRACE', expected=False):
        print("  [OK] TRACE dropped by IDS")
    else:
        print("  [FAIL] TRACE forwarded to LB")
        all_ok = False

    # Code-injection via PUT should be dropped/redirected to inspector
    print("==> Testing IDS code-injection catch")
    evil = "cat /etc/passwd"
    if testing.curl(h1, VIP, method='PUT', payload=evil, expected=False):
        print("  [OK] Injection dropped by IDS → insp")
    else:
        print("  [FAIL] Injection made it through IDS")
        all_ok = False

    return all_ok

if __name__ == "__main__":

    # Create topology
    topo = MyTopo()

    # Create controller
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

    # Launch HTTP servers, packet captures, and set routes
    startup_services(net)

    # Run automated tests
    run_tests(net)
    print(f"\n=== ALL TESTS {'PASSED' if success else 'FAILED'} ===\n")

    # If any test failed, drop into the CLI for debugging
    if not success:
        CLI(net)

    # Clean up and exit with appropriate status code
    net.stop()
    sys.exit(0 if success else 1)
