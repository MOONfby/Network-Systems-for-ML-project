// 2 variables to hold ports names
// Define the two interfaces (ports) for the NAPT module
// $PORT1: connects to the User Zone (h1, h2 side)
// $PORT2: connects to the Inferencing Zone (servers side)
define($PORT1 napt-eth1, $PORT2 napt-eth2)

//require(library ./forwarder.click)
//Forwarder($PORT1, $PORT2, $VERBOSE)

// Script will run as soon as the router starts
// Print a startup banner so we know the script is running and on which ports
Script(print "Click NAPT router on $PORT1 $PORT2")


// From where to pick packets
// FromDevice elements capture incoming packets on each interface
// SNIFFER false: remove original packet to avoid duplicates
// PROMISC true: receive all frames, even if not addressed to us
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)


// Counters for packet rates (AveragePacketRate) right after FromDevice
inAvg1::AverageCounter()   // measure ingress rate on PORT1
inAvg2::AverageCounter()   // measure ingress rate on PORT2

// Send packets back out each interface
// AverageCounter right before each ToDevice measures egress rate
outAvg1::AverageCounter()  // measure egress rate on PORT1
outAvg2::AverageCounter()  // measure egress rate on PORT2


// Where to send packets
// ToDevice elements send outgoing packets back out the specified interface
td1::ToDevice($PORT1, METHOD LINUX)
td2::ToDevice($PORT2, METHOD LINUX)



// ARP responder for User Zone interface
// Replies to ARP requests for IP 10.0.0.1 with MAC 02:00:00:00:00:01
user_arp_responder :: ARPResponder(10.0.0.1 02:00:00:00:00:01);

// ARP responder for Inferencing Zone interface
// Replies to ARP requests for IP 100.0.0.1 with MAC 02:00:00:00:00:02
inf_arp_responder  :: ARPResponder(100.0.0.1 02:00:00:00:00:02);


// IPRewriter for TCP source-NAT on outbound direction
// Converts 10.0.0.0/24 -> 100.0.0.0/24 preserving port ranges
snat :: IPRewriter(
    10.0.0.0/24, 10.0.0.1, 0-65535,
    100.0.0.0/24, 100.0.0.1, 0-65535
)

// IPRewriter for TCP destination-NAT on inbound direction
// Converts 100.0.0.0/24 -> 10.0.0.0/24 preserving port ranges
dnat :: IPRewriter(
    100.0.0.0/24, 100.0.0.1, 0-65535,
    10.0.0.0/24, 10.0.0.1, 0-65535
)


// ICMPPingRewriter for ICMP (ping) source-NAT outbound
icmp_snat :: ICMPPingRewriter(10.0.0.0/24, 100.0.0.1)

// ICMPPingRewriter for ICMP (ping) destination-NAT inbound
icmp_dnat :: ICMPPingRewriter(100.0.0.0/24, 10.0.0.1)



// Traffic class counters for User-Zone side
arpCnt1::Counter("ARP_in")          // counts ARP requests/replies
tcpCnt1::Counter("TCP_in")          // counts TCP packets for NAT
icmpCnt1::Counter("ICMP_in")        // counts ICMP echo requests/replies
dropCnt1::Counter("DROP_IP_in")     // counts non-TCP/ICMP IPv4 packets dropped
dropL2_1::Counter("DROP_L2_in")     // counts non-ARP, non-IPv4 frames dropped

// Traffic class counters for Inferencing-Zone side
arpCnt2::Counter("ARP_in")          // counts ARP requests/replies
tcpCnt2::Counter("TCP_in")          // counts TCP packets for NAT
icmpCnt2::Counter("ICMP_in")        // counts ICMP echo requests/replies
dropCnt2::Counter("DROP_IP_in")     // counts non-TCP/ICMP IPv4 packets dropped
dropL2_2::Counter("DROP_L2_in")     // counts non-ARP, non-IPv4 frames dropped




// -------- User-Zone Side Pipeline (napt-eth1) --------
fd1                           // input packets from User Zone
    -> inAvg1                  // count ingress rate on PORT1
    -> eth1::Classifier(
         12/0x0806,           // ARP frames → output port 0
         12/0x0800,           // IPv4 packets → output port 1
         -                    // all other frames → output port 2
       )

// Handle ARP frames: respond and send back out same interface
eth1[0] -> arpCnt1                  
         -> user_arp_responder      // generate ARP reply for IP 10.0.0.1
         -> Queue                   // queue up for transmission
         -> outAvg1                 // count egress rate before PORT1
         -> td1                     // send out on PORT1

// Handle IPv4 packets: classify by IP protocol type
eth1[1] -> ip1::Classifier(
         14/tcp,              // TCP → output port 0
         14/icmp,             // ICMP → output port 1
         -                    // other IP → drop (output port 2)
       )
// TCP branch: apply source-NAT then forward to servers
ip1[0]   -> tcpCnt1        
         -> snat          
         -> Queue         
         -> outAvg2       // count egress before PORT2
         -> td2           // send out on PORT2
// ICMP branch: apply ICMP source-NAT then forward
ip1[1]   -> icmpCnt1      
         -> icmp_snat     
         -> Queue         
         -> outAvg2       // count egress before PORT2
         -> td2           // send out on PORT2
// Other IP: drop any non-TCP/non-ICMP IPv4 packets
ip1[2]   -> dropCnt1      
         -> Discard       
// Other L2 traffic: drop frames that are not ARP or IPv4
eth1[2] -> dropL2_1       
         -> Discard       




// -------- Inferencing-Zone Side Pipeline (napt-eth2) --------
fd2                           // input packets from Inferencing Zone
    -> inAvg2                  // count ingress rate on PORT2
    -> eth2::Classifier(
         12/0x0806,           // ARP frames → output port 0
         12/0x0800,           // IPv4 packets → output port 1
         -                    // all other frames → output port 2
       )

// Handle ARP frames: respond with server-side ARP
eth2[0] -> arpCnt2                  
         -> inf_arp_responder        // ARP reply for IP 100.0.0.1
         -> Queue                   // queue for sending
         -> outAvg2                 // count egress rate before PORT2
         -> td2                     // send out on PORT2

// Handle IPv4 packets: classify by protocol
eth2[1] -> ip2::Classifier(
         14/tcp,              // TCP → output port 0
         14/icmp,             // ICMP → output port 1
         -                    // other IP → drop
       )
// TCP branch: apply destination-NAT then forward to users
ip2[0]   -> tcpCnt2        
         -> dnat          
         -> Queue         
         -> outAvg1       // count egress before PORT1
         -> td1           // send out on PORT1
// ICMP branch: apply ICMP destination-NAT then forward
ip2[1]   -> icmpCnt2      
         -> icmp_dnat     
         -> Queue         
         -> outAvg1       // count egress before PORT1
         -> td1           // send out on PORT1
// Other IP: drop any non-TCP/non-ICMP IPv4 packets
ip2[2]   -> dropCnt2      
         -> Discard       
// Other L2 traffic: drop frames that are not ARP or IPv4
eth2[2] -> dropL2_2       
         -> Discard     



// Print something on exit
// DriverManager will listen on router's events
// The pause instruction will wait until the process terminates
// Then the prints will run an Click will exit

// DriverManager keeps script alive and prints summary on shutdown
// Write counters to napt.report on shutdown
DriverManager(
    
    file "result/napt.report",
    print "Shutting down NAPT router",  // log shutdown event
    pause,                              // wait for termination signal

    // Ingress/Egress rates
    print "Port1 InRate (pps): $(inAvg1.rate)",
    print "Port1 OutRate (pps): $(outAvg1.rate)",
    print "Port2 InRate (pps): $(inAvg2.rate)",
    print "Port2 OutRate (pps): $(outAvg2.rate)",

    // User-Zone counts
    print "ARP packets (in1): $(arpCnt1.count)",
    print "TCP packets (in1): $(tcpCnt1.count)",
    print "ICMP packets (in1): $(icmpCnt1.count)",
    print "Dropped IP (in1): $(dropCnt1.count)",
    print "Dropped L2 (in1): $(dropL2_1.count)",

    // Inferencing-Zone counts
    print "ARP packets (in2): $(arpCnt2.count)",
    print "TCP packets (in2): $(tcpCnt2.count)",
    print "ICMP packets (in2): $(icmpCnt2.count)",
    print "Dropped IP (in2): $(dropCnt2.count)",
    print "Dropped L2 (in2): $(dropL2_2.count)"
)
