define($VIRTUAL_IP 100.0.0.45, $VIRTUAL_MAC 00:00:00:00:00:45)

// Port definitions matching actual Mininet interface names
define($PORT1 lb1-eth1, $PORT2 lb1-eth2)
// eth1: between ids and lb1
// eth2: between lb1 and sw3

// Script will run as soon as the router starts
Script(print "Click lb1 on $PORT1 $PORT2")

// Input channels from devices
// "SNIFFER false" allows click steals the packet from the kernel
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

// Output channels to devices
td1::ToDevice($PORT1, METHOD LINUX)
td2::ToDevice($PORT2, METHOD LINUX)

// Traffic counters for reporting
avg_in1 :: AverageCounter
avg_in2 :: AverageCounter
avg_out1 :: AverageCounter
avg_out2 :: AverageCounter

// ARP Handling Elements, ensures hosts can sesolve virtual IP to virtual MAC
arpr :: ARPResponder($VIRTUAL_IP $VIRTUAL_MAC)
arpq :: ARPQuerier($VIRTUAL_IP, $VIRTUAL_MAC)
// arpq has two input ports：
// input 0: For IP packets that need ARP resolution
// input 1: For ARP replies (so the ARPQuerier can update its ARP cache/table with new information)


// Round Robin Mapper for Load Balancing HTTP traffic
rr_mapper :: RoundRobinIPMapper($VIRTUAL_IP 80 - -    
                               100.0.0.40 80 - 
                               100.0.0.41 80 - 
                               100.0.0.42 80)
rewriter :: IPRewriter(pattern rr_mapper)             
// input 0: handles the packets from clients to the virtual IP
// input 1: handles the packets from servers back to the clients


// Counters for specific traffic types
arp_req_counter :: Counter    //ARP requests
arp_resp_counter :: Counter   //ARP responses
service_counter :: Counter    //HTTP service packets
icmp_counter :: Counter       //ICMP
drop_counter :: Counter       //dropped packets







// From IDS to servers pathway
// numbers are packer header match patterns
// "12/0806": 12 means offset 12 bytes from the start of the packet (Ethernet header's EtherType field), 0806 is the EtherType for ARP
// "20/0001": means offset 32 bytes from the start, 0001 is the ARP opcode for "request"
fd1 -> avg_in1 -> classifier1 :: Classifier(
    12/0806 20/0001,  // ARP requests
    12/0806 20/0002,  // ARP replies
    12/0800,          // IP packets
    -                 // Drop others
)


// ARP Request Handling (from IDS side)
classifier1[0] -> arp_req_counter -> arpr -> avg_out1 -> td1
// takes ARP requests from the classifier ->
// count->
// ARPResponder generates replies claiming the virtual IP belongs to the virtual MAC ->
// count ->
// sends reply back through the interface toward IDS


// ARP Reply Handling (from IDS side)
classifier1[1] -> arp_resp_counter -> [1]arpq -> avg_out1 -> td1
// [1]arpq: sends to the ARPQuerier to update its ARP table


// IP Packet Processing (from IDS side)
classifier1[2] -> Strip(14) -> CheckIPHeader -> ip_classifier :: IPClassifier(
    proto icmp,                 // ICMP (ping)
    proto tcp and dst port 80,  // HTTP traffic
    -                           // Other IP traffic
)
// strip(14): strips the 14-byte Ethernet header


// ICMP handling
ip_classifier[0] -> icmp_counter -> ICMPPingResponder -> EtherEncap(0x0800, $VIRTUAL_MAC, 00:00:00:00:00:01) -> avg_out1 -> td1
// ICMPPingResponder: generates replies to echo requests
// EtherEncap: adds Ethernet header with virtual MAC as source


// HTTP traffic - forward to servers using load balancer
ip_classifier[1] -> service_counter -> [0]rewriter -> arpq -> avg_out2 -> td2
// [0]rewriter: sends to rewriter (IPRewriter) for address translation based on the round-robin mapping
// arpq: uses ARP querier to resolve server IPs to MACs


// Drop other IP traffic
ip_classifier[2] -> drop_counter -> Discard








// From servers to IDS pathway
fd2 -> avg_in2 -> classifier2 :: Classifier(
    12/0806 20/0001,  // ARP requests
    12/0806 20/0002,  // ARP replies
    12/0800,          // IP packets
    -                 // Drop others
)


// Return traffic from servers
classifier2[2] -> Strip(14) -> CheckIPHeader -> IPClassifier(
    src 100.0.0.40 or src 100.0.0.41 or src 100.0.0.42, // From servers
    -                                                   // Other sources
) -> [1]rewriter -> arpq -> avg_out1 -> td1


// ARP handling from server side
classifier2[0] -> td2
classifier2[1] -> td2
classifier2[3] -> drop_counter -> Discard







// Generate report on shutdown
DriverManager(
    pause,
    print > result/lb1.report "================= LB1 Report =================",
    print > result/lb1.report "Input Packet rate (pps): $(avg_in1.rate) $(avg_in2.rate)",
    print > result/lb1.report "Output Packet rate (pps): $(avg_out1.rate) $(avg_out2.rate)",
    print > result/lb1.report "",
    print > result/lb1.report "Total # of input packets: $(add $(avg_in1.count) $(avg_in2.count))",
    print > result/lb1.report "Total # of output packets: $(add $(avg_out1.count) $(avg_out2.count))",
    print > result/lb1.report "",
    print > result/lb1.report "Total # of ARP requests: $(arp_req_counter.count)",
    print > result/lb1.report "Total # of ARP responses: $(arp_resp_counter.count)",
    print > result/lb1.report "",
    print > result/lb1.report "Total # of service packets: $(service_counter.count)",
    print > result/lb1.report "Total # of ICMP packets: $(icmp_counter.count)",
    print > result/lb1.report "Total # of dropped packets: $(drop_counter.count)",
    print > result/lb1.report "================================================"
)
