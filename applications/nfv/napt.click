// 2 variables to hold ports names
// Define the two interfaces (ports) for the NAPT module
// $PORT1: connects to the User Zone (h1, h2 side)
// $PORT2: connects to the Inferencing Zone (servers side)
define($PORT1 napt-eth1, $PORT2 napt-eth2);
define($PORT1_MAC  02:00:00:00:00:01, $PORT2_MAC  02:00:00:00:00:02);

//require(library ./forwarder.click)
//Forwarder($PORT1, $PORT2, $VERBOSE)

// Script will run as soon as the router starts
// Print a startup banner so we know the script is running and on which ports
Script(print "Click NAPT router on $PORT1 $PORT2");


// From where to pick packets
// FromDevice elements capture incoming packets on each interface
// SNIFFER false: remove original packet to avoid duplicates
// PROMISC true: receive all frames, even if not addressed to us
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true);
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true);


// Counters for packet rates (AveragePacketRate) right after FromDevice
inAvg1::AverageCounter();   // measure ingress rate on PORT1
inAvg2::AverageCounter();   // measure ingress rate on PORT2

// Send packets back out each interface
// AverageCounter right before each ToDevice measures egress rate
outAvg1::AverageCounter();  // measure egress rate on PORT1
outAvg2::AverageCounter();  // measure egress rate on PORT2


// Where to send packets
// ToDevice elements send outgoing packets back out the specified interface
td1::ToDevice($PORT1, METHOD LINUX);
td2::ToDevice($PORT2, METHOD LINUX);


// -------------------- Network Functions --------------------

// ARP Responders for User and Inferencing Zones
// Responds to ARP requests asking for 10.0.0.1 (User Zone side).
user_arp_responder :: ARPResponder(10.0.0.1  $PORT1_MAC);
// Responds to ARP requests asking for 100.0.0.1 (Inferencing Zone side).
inf_arp_responder  :: ARPResponder(100.0.0.1 $PORT2_MAC);

// ARP queriers so that Click learns next-hop MAC before sending
arpQueryOut :: ARPQuerier(100.0.0.45, $PORT2_MAC);  // for traffic heading into IZ
arpQueryIn  :: ARPQuerier(10.0.0.1,   $PORT1_MAC);  // for traffic heading back to UZ

// IP and ICMP Rewriters
// - snat: Source NAT for outbound TCP (User -> Server).
// - dnat: Destination NAT for inbound TCP (Server -> User).
snat :: IPRewriter(10.0.0.0/24, 10.0.0.1, 0-65535, 100.0.0.0/24, 100.0.0.1, 0-65535);
dnat :: IPRewriter(100.0.0.0/24, 100.0.0.1, 0-65535, 10.0.0.0/24, 10.0.0.1, 0-65535);


// Handles translation for ICMP packets (Ping):
// - icmp_snat: for ICMP Echo Requests outbound.
// - icmp_dnat: for ICMP Echo Replies inbound.
icmp_snat :: ICMPPingRewriter(10.0.0.0/24, 100.0.0.1);
icmp_dnat :: ICMPPingRewriter(100.0.0.0/24, 10.0.0.1);

// Traffic counters
arpCnt1, arpCnt2 :: Counter("ARP");            // ARP packets
tcpCnt1, tcpCnt2 :: Counter("TCP");            // TCP packets
icmpCnt1, icmpCnt2 :: Counter("ICMP");         // ICMP packets
dropCnt1, dropCnt2 :: Counter("IP_DROPPED");   // Dropped IP packets
dropL2_1, dropL2_2 :: Counter("L2_DROPPED");   // Dropped Ethernet frames

// Classifiers for Ethernet type
ethClassifier1 :: Classifier(
    12/0806 20/0001, // ARP Request
    12/0806 20/0002, // ARP Reply
    12/0800,         // IPv4 Packet
    -                // Other
);

ethClassifier2 :: Classifier(
    12/0806 20/0001, // ARP Request
    12/0806 20/0002, // ARP Reply
    12/0800,         // IPv4 Packet
    -                // Other
);

// IP Classifiers for protocols inside IPv4
ipClassifier1 :: IPClassifier(
    tcp,                    // - TCP
    icmp type echo,         // - ICMP Echo Request
    icmp type echo-reply,   // - ICMP Echo Reply
    -                       // - All other (drop)
);

ipClassifier2 :: IPClassifier(
    tcp,                    // - TCP
    icmp type echo,         // - ICMP Echo Request
    icmp type echo-reply,   // - ICMP Echo Reply
    -                       // - All other (drop)
);

// ======================= USER ZONE PIPELINE =======================
fd1 -> inAvg1 -> ethClassifier1;

// Handle ARP request/reply
ethClassifier1[0] -> arpCnt1 -> user_arp_responder -> outAvg1 -> td1;
ethClassifier1[1] -> arpCnt1 -> user_arp_responder -> outAvg1 -> td1;

// IPv4 packets
ethClassifier1[2]
    -> Strip(14)        // Remove Ethernet header (14 bytes)
    -> CheckIPHeader    // Validate IP header checksum
    -> ipClassifier1;    // Classify IP payload

// TCP packets (Outbound traffic)
// TCP: Source NAT then forward
ipClassifier1[0] -> tcpCnt1 -> snat -> Queue -> arpQueryOut -> outAvg2 -> td2;

// ICMP Echo Request (Ping Outbound)
// ICMP Echo Request: NAT and forward
ipClassifier1[1] -> icmpCnt1 -> Queue -> arpQueryOut -> outAvg2 -> td2;

// ICMP Echo Reply (not expected from User Zone) — drop
ipClassifier1[2] -> dropCnt1 -> Discard;

// Other IP traffic — drop
ipClassifier1[3] -> dropCnt1 -> Discard;

// Other (non-IP, non-ARP) Ethernet frames - drop
ethClassifier1[3] -> dropL2_1 -> Discard;

// ======================= INFERENCING ZONE PIPELINE =======================
fd2 -> inAvg2 -> ethClassifier2;

// Handle ARP request/reply
ethClassifier2[0] -> arpCnt2 -> inf_arp_responder -> outAvg2 -> td2;   // ARP Requests
ethClassifier2[1] -> arpCnt2 -> inf_arp_responder -> outAvg2 -> td2;   // ARP Replies

// IPv4 packets
ethClassifier2[2]
    -> Strip(14)        // Remove Ethernet header
    -> CheckIPHeader    // Validate IP header
    -> ipClassifier2;    // Classify IP payload

// TCP packets (Inbound traffic)
// TCP: Destination NAT then forward
ipClassifier2[0] -> tcpCnt2 -> dnat -> Queue -> arpQueryIn -> outAvg1 -> td1;

// ICMP Echo Request (from servers)
// ICMP Echo Request: NAT and forward
ipClassifier2[1] -> icmpCnt2 -> Queue -> arpQueryIn -> outAvg1 -> td1;

// ICMP Echo Reply (from servers)
// ICMP Echo Reply: NAT and forward
ipClassifier2[2] -> icmpCnt2 -> Queue -> arpQueryIn -> outAvg1 -> td1;

// Other IP traffic — drop
ipClassifier2[3] -> dropCnt2 -> Discard;

// Other (non-IP, non-ARP) Ethernet frames — drop
ethClassifier2[3] -> dropL2_2 -> Discard;


// Print something on exit
// DriverManager will listen on router's events
// The pause instruction will wait until the process terminates
// Then the prints will run an Click will exit

// DriverManager keeps script alive and prints summary on shutdown
// Write counters to napt.report on shutdown
DriverManager(
  file "result/napt.report",
  print "=============== NAPT Report ===============",
  print "Port1 InRate (pps): $(inAvg1.rate)",
  print "Port1 OutRate (pps): $(outAvg1.rate)",
  print "Port2 InRate (pps): $(inAvg2.rate)",
  print "Port2 OutRate (pps): $(outAvg2.rate)",
  print "ARP packets (in1): $(arpCnt1.count)",
  print "TCP packets (in1): $(tcpCnt1.count)",
  print "ICMP packets (in1): $(icmpCnt1.count)",
  print "Dropped IP (in1): $(dropCnt1.count)",
  print "Dropped L2 (in1): $(dropL2_1.count)",
  print "ARP packets (in2): $(arpCnt2.count)",
  print "TCP packets (in2): $(tcpCnt2.count)",
  print "ICMP packets (in2): $(icmpCnt2.count)",
  print "Dropped IP (in2): $(dropCnt2.count)",
  print "Dropped L2 (in2): $(dropL2_2.count)"
);
