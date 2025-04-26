define($VIRTUAL_IP 100.0.0.45, $VIRTUAL_MAC 00:00:00:00:00:45)

// Port definitions matching actual Mininet interface names
define($PORT1 lb1-eth1, $PORT2 lb1-eth2)
//eth1: between ids and lb1
//eth2: between lb1 and sw3


// Input channels from devices
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

// ARP Handling Elements
arpr :: ARPResponder($VIRTUAL_IP $VIRTUAL_MAC)
arpq :: ARPQuerier($VIRTUAL_IP, $VIRTUAL_MAC)

// Round Robin Mapper for Load Balancing
rr_mapper :: RoundRobinIPMapper($VIRTUAL_IP 80 - - 
                               100.0.0.40 80 - 
                               100.0.0.41 80 - 
                               100.0.0.42 80)
rewriter :: IPRewriter(pattern rr_mapper)

// Counters for specific traffic types
arp_req_counter :: Counter
arp_resp_counter :: Counter
service_counter :: Counter
icmp_counter :: Counter
drop_counter :: Counter

// From IDS to servers pathway
fd1 -> avg_in1 -> classifier1 :: Classifier(
    12/0806 20/0001,  // ARP requests
    12/0806 20/0002,  // ARP replies
    12/0800,          // IP packets
    -                 // Drop others
)

// ARP Request Handling (from IDS side)
classifier1[0] -> arp_req_counter -> arpr -> avg_out1 -> td1

// ARP Reply Handling (from IDS side)
classifier1[1] -> arp_resp_counter -> [1]arpq -> avg_out1 -> td1

// IP Packet Processing (from IDS side)
classifier1[2] -> Strip(14) -> CheckIPHeader -> ip_classifier :: IPClassifier(
    proto icmp,                 // ICMP (ping)
    proto tcp and dst port 80,  // HTTP traffic
    -                           // Other IP traffic
)

// ICMP handling
ip_classifier[0] -> icmp_counter -> ICMPPingResponder -> EtherEncap(0x0800, $VIRTUAL_MAC, 00:00:00:00:00:01) -> avg_out1 -> td1

// HTTP traffic - forward to servers using load balancer
ip_classifier[1] -> service_counter -> [0]rewriter -> arpq -> avg_out2 -> td2

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
    print > lb1.report "================= LB1 Report =================",
    print > lb1.report "Input Packet rate (pps): $(avg_in1.rate) $(avg_in2.rate)",
    print > lb1.report "Output Packet rate (pps): $(avg_out1.rate) $(avg_out2.rate)",
    print > lb1.report "",
    print > lb1.report "Total # of input packets: $(add $(avg_in1.count) $(avg_in2.count))",
    print > lb1.report "Total # of output packets: $(add $(avg_out1.count) $(avg_out2.count))",
    print > lb1.report "",
    print > lb1.report "Total # of ARP requests: $(arp_req_counter.count)",
    print > lb1.report "Total # of ARP responses: $(arp_resp_counter.count)",
    print > lb1.report "",
    print > lb1.report "Total # of service packets: $(service_counter.count)",
    print > lb1.report "Total # of ICMP packets: $(icmp_counter.count)",
    print > lb1.report "Total # of dropped packets: $(drop_counter.count)",
    print > lb1.report "================================================"
)
