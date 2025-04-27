// Define the port names
// * eth0: Default port of Mininet host
// * eth1: Port connected to the sw2
// * eth2: Port connected to the Insp device
// * eth3: Port connected to the lb1
define($IN ids-eth1, $INSP ids-eth2, $OUT ids-eth3)

// Define the report path
define($REPORT_PATH results/ids.report)

// Script will run as soon as the router starts
Script(print "IDS forwarder on $IN $OUT, IDS connect Insp via $INSP")

// From where to pick packets
fd_in :: FromDevice($IN, SNIFFER false)
fd_out :: FromDevice($OUT, SNIFFER false)

// Where to send packets
td_in :: ToDevice($IN)
td_out :: ToDevice($OUT)
td_insp :: ToDevice($INSP)

// Define counter of packets throughput
rate_fd_in :: AverageCounter
rate_td_out :: AverageCounter
rate_td_insp :: AverageCounter

ctr_fd_in_ :: Counter
ctr_td_out :: Counter
ctr_td_insp :: Counter

// Packet Classifier
// ===== Level 1: Ethernet header =====

// ==================
// Counter of ethernet classifier
// 1. ctr_arp: ARP packets
// 2. ctr_ip: IPv4 packets (e.g., ICMP, TCP, UDP etc.)
// 3. ctr_ethernet_drop: Others
// =================
ctr_arp :: Counter
ctr_ip :: Counter
ctr_ethernet_drop :: Counter

// ==================
// element: ethernet_classifier
// Description: Classify the packet with Ethernet header
//
// 1. ARP transparently transmitted to the output port
// 2. IPv4 for further classification
// 3. Others dropped
// =================

ethernet_classifier :: Classifier(
	12/0806,    // ARP (offset 12, ARP 0x0806)
	12/0800,    // IPv4 (offset 12, IPv4 0x0800)
	-           // Others
  )

// ===== Level 2: IP + TCP header =====

// ==================
// Counter of ip classifier
// 1. ctr_icmp: ICMP packets
// 2. ctr_http: http packets
// 3. Others dropped
// =================
ctr_icmp :: Counter
ctr_http :: Counter
ctr_ip_drop :: Counter

// ==================
// element: ip_classifier
// Description: Classify the IP packet
//
// 1. ICMP packets transparently transmitted to the output port
// 2. HTTP packets (TCP port 80) for further classification
// 3. Others dropped
// ==============
ip_classifier :: IPClassifier(
	icmp,				// ICMP packets
	tcp dst port 80,	// HTTP packets (TCP port 80)
	-					//Others
)

// ===== Level 3: HTTP payload =====

// ==================
// element: tcp_lengh_check
// Description: Check the length of the TCP packet
// 1. [0] <=54: no payload, TCP signaling
// 2. [1] >54: has payload
// ==================

ctr_tcp_signaling :: Counter
tcp_lengh_check :: LengthFilter(>54)

// ==================
// Counter of ethernet classifier
// 1. ctr_post: POST method
// 2. ctr_put: PUT method
// 3. ctr_method_drop: Others
// =================

ctr_post :: Counter;
ctr_put :: Counter;
ctr_method_drop :: Counter;

// ==================
// element: method_classifier
// Description: Classify the TCP payload
//
// 1. Offset 54: Ethernet header + IP header + TCP header
// 2. Classify PUT and POST methods
// 3. Others sent to insp
// ==============

method_classifier :: Classifier(
	// Offset 54: Ethernet header + IP header + TCP header
	54/504F5354, // "POST"
    54/50555420, // "PUT "
    -           // Others
)

// Level 4: Injection in PUT method

ctr_pw :: Counter
ctr_log :: Counter
ctr_insert :: Counter
ctr_update :: Counter
ctr_delete :: Counter
ctr_inject_drop :: Counter

// Search for the end of the HTTP header
search_payload :: Search("\r\n\r\n");
payload_check :: Classifier(
	// Offset 0: Pointer move to the end of the payload after search_payload
	0/636174202f6574632f706173737764,  // cat /etc/passwd
	0/636174202f7661722f6c6f672f,      // cat /var/log/
	0/494e53455254,                    // INSERT
	0/555044415445,                    // UPDATE
	0/44454c455445,                    // DELETE
	-
);



// ===== Data flow =====
// Flow in
fd_in -> ctr_fd_in -> rate_fd_in -> ether_classifier;

// Level 1: Ethernet header
// ARP forwarded to the output port
ether_classifier[0] -> ctr_arp -> Queue -> ctr_td_out -> rate_td_out -> td_out;
// IPv4 packets for further classification
ether_classifier[1] -> ctr_ip -> ip_classifier;
// Other to insp
ether_classifier[2] -> ctr_ethernet_drop -> Queue -> ctr_td_insp -> rate_td_insp -> td_insp;

// Level 2: IP header + TCP header
// ICMP forwarded to the output port
ip_classifier[0] -> ctr_icmp -> Queue -> ctr_td_out -> rate_td_out -> td_out;
// HTTP packets for further classification
ip_classifier[1] -> ctr_http -> tcp_lengh_check;
// Other to insp
ip_classifier[2] -> ctr_ip_drop -> Queue -> ctr_td_insp -> rate_td_insp -> td_insp;

// Level 3: HTTP payload
// Payload <= 54 Bytes, TCP signaling forwarded to the output port
tcp_lengh_check[0] -> ctr_tcp_signaling -> Queue -> ctr_td_out -> rate_td_out -> td_out;
// Other for further classification
tcp_lengh_check[1] -> method_classifier;
// POST method to lb1
method_classifier[0] -> ctr_post -> Queue -> ctr_td_out -> rate_td_out -> td_out;
// PUT method for further classification
method_classifier[1] -> ctr_put -> search_payload -> payload_check;
// Other to insp
method_classifier[2] -> ctr_method_drop -> Queue -> ctr_td_insp -> rate_td_insp -> td_insp;

// Level 4: Injection in PUT method
// cat /etc/passwd to lb1
payload_check[0] -> ctr_pw -> Queue -> ctr_td_out -> rate_td_out -> td_out;
// cat /var/log/ to lb1
payload_check[1] -> ctr_log -> Queue -> ctr_td_out -> rate_td_out -> td_out;
// INSERT to lb1
payload_check[2] -> ctr_insert -> Queue -> ctr_td_out -> rate_td_out -> td_out;
// UPDATE to lb1
payload_check[3] -> ctr_update -> Queue -> ctr_td_out -> rate_td_out -> td_out;
// DELETE to lb1
payload_check[4] -> ctr_delete -> Queue -> ctr_td_out -> rate_td_out -> td_out;
// Other to insp
payload_check[5] -> ctr_inject_drop -> Queue -> ctr_td_insp -> rate_td_insp -> td_insp;

// Report output
DriverManager(
	pause,
	
	// After user press Ctrl+C, the script will run and print the report
    print "=== IDS REPORT ===",
	print "Input Packet rate (pps): $(rate_fd_in.rate)",
	print "Output Packet rate (pps): $(rate_td_out.rate)",
	print "Insp Packet rate (pps): $(rate_td_insp.rate)",
	print "",
	print "Total # of Input Packet: $(ctr_fd_in.count)",
	print "Total # of Output Packet: $(ctr_td_out.count)",
	print "Total # of Insp Packet: $(ctr_td_insp.count)",
	print "===================",
	print "Level 1: Ethernet header",
	print "Total # of ARP Packets: $(ctr_arp.count)",
	print "Total # of IPv4 Packets: $(ctr_ip.count)",
	print "Total # Ethenet drop Packets: $(ctr_ethernet_drop.count)",
	print "",
	print "Level 2: IP header + TCP header",
	print "Total # of ICMP Packets: $(ctr_icmp.count)",
	print "Total # of HTTP Packets: $(ctr_http.count)",
	print "Total # of IP drop Packets: $(ctr_ip_drop.count)",
	print "",
	print "Level 3: HTTP payload",
	print "Total # of TCP signaling Packets: $(ctr_tcp_signaling.count)",
	print "Total # of POST Packets: $(ctr_post.count)",
	print "Total # of PUT Packets: $(ctr_put.count)",
	print "Total # of Other Method Packets (to INSP): $(ctr_method_drop.count)",
	print "",
	print "Level 4: Injection in PUT method",
	print "Total # of cat /etc/passwd Packets: $(ctr_pw.count)",
	print "Total # of cat /var/log Packets: $(ctr_log.count)",
	print "Total # of cat /etc/passwd Packets: $(ctr_pw.count)",
	print "Total # of INSERT Packets: $(ctr_insert.count)",
	print "Total # of UPDATE Packets: $(ctr_update.count)",
	print "Total # of DELETE Packets: $(ctr_delete.count)",
	print "Total # of Other Payload (to INSP): $(ctr_inject_drop.count)",
    print "===================",
    print > $REPORT_PATH,
)