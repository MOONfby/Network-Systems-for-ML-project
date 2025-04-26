// Define the port names
// * eth0: Default port of Mininet host
// * eth1: Port connected to the sw2
// * eth2: Port connected to the Insp device
// * eth3: Port connected to the lb1
define($IN ids-eth1, $INSP ids-eth2, $OUT ids-eth3)

// Define the report path
define($REPORT_PATH /results/ids_report.txt)

// Script will run as soon as the router starts
Script(print "Click forwarder on $IN $OUT\nClick connect Insp via $INSP")

// From where to pick packets
fd_in :: FromDevice($IN, SNIFFER false)
fd_out :: FromDevice($OUT, SNIFFER false)

// Where to send packets
td_in :: ToDevice($IN)
td_out :: ToDevice($OUT)
td_insp :: ToDevice($INSP)

// Define counter of packets throughput
ctr_fd_in :: AverageCounter
ctr_fd_out :: AverageCounter
ctr_td_in :: AverageCounter
ctr_td_out :: AverageCounter
ctr_td_insp :: AverageCounter

// ==================
// Define the counter of packets traffic class
// 1. ctr_ethernet: Ethernet packets (e.g., ARP, IPv4 etc.)
// 2. ctr_ip: IP packets (e.g., ICMP, TCP, UDP etc.)
// 3. ctr_icmp: ICMP packets (e.g., ping, traceroute etc.)
// 4. ctr_http: HTTP packets (TCP port 80)
// 5. ctr_http_method: http_method packets (e.g., GET, POST, PUT etc.)
// 6. ctr_payload: payload packets (e.g., TCP payload, UDP payload etc.)
// ===================

ctr_ethernet :: AverageCounter
ctr_ip :: AverageCounter
ctr_icmp :: AverageCounter
ctr_http :: AverageCounter
ctr_http_method :: AverageCounter
ctr_payload :: AverageCounter


// Group common elements in a single block. $port is a parameter used just to print
elementclass L2Forwarder {$port|
	input
	->cnt::Counter
        ->Print
	->Queue
	->output
}

// From where to pick packets
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

// Where to send packets
td1::ToDevice($PORT1, METHOD LINUX)
td2::ToDevice($PORT2, METHOD LINUX)

// Instantiate 2 forwarders, 1 per directions
fd1->fwd1::L2Forwarder($PORT1)->td2
fd2->fwd2::L2Forwarder($PORT2)->td1


// Print something on exit
// DriverManager will listen on router's events
// The pause instruction will wait until the process terminates
// Then the prints will run an Click will exit
DriverManager(
        print "Router starting",
        pause,
	print "Packets from ${PORT1}: $(fwd1/cnt.count)",
	print "Packets from ${PORT2}: $(fwd2/cnt.count)",
)
