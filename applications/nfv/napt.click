// 2 variables to hold ports names
define($PORT1 napt-eth1, $PORT2 napt-eth2)
//require(library ./forwarder.click)
//Forwarder($PORT1, $PORT2, $VERBOSE)
// Script will run as soon as the router starts
Script(print "Click NAPT router on $PORT1 $PORT2")

// Group common elements in a single block. $port is a parameter used just to print
//elementclass L2Forwarder {$port|
//	input
//	->cnt::Counter
//	->Classifier(
//        12/0806, // ARP
//        12/0800, // IP
//        -        // others
//    )
//	->output
//}

// From where to pick packets
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

// Where to send packets
td1::ToDevice($PORT1, METHOD LINUX)
td2::ToDevice($PORT2, METHOD LINUX)


// Counters for input packet rates
inCnt1::Counter( )
inCnt2::Counter( )


// ARP Responders
user_arp_responder :: ARPResponder(10.0.0.1 02:00:00:00:00:01);
inf_arp_responder  :: ARPResponder(100.0.0.1 02:00:00:00:00:02);


// NAPT for TCP
snat :: IPRewriter(
    10.0.0.0/24, 10.0.0.1, 0-65535,
    100.0.0.0/24, 100.0.0.1, 0-65535
)
dnat :: IPRewriter(
    100.0.0.0/24, 100.0.0.1, 0-65535,
    10.0.0.0/24, 10.0.0.1, 0-65535
)

// NAPT for ICMP
icmp_snat :: ICMPPingRewriter(10.0.0.0/24, 100.0.0.1)
icmp_dnat :: ICMPPingRewriter(100.0.0.0/24, 10.0.0.1)




// Topology on user-zone side (napt-eth1)
fd1 \
    -> inCnt1 \
    -> eth1::Classifier(12/0x0806, 12/0x0800, -)  // ARP, IPv4, others
// ARP
eth1[0] -> user_arp_responder -> Queue -> td1;
// IP
eth1[1] -> ip1::Classifier(14/tcp, 14/icmp, -);
//   TCP SNAT
ip1[0] -> snat -> Queue -> td2;
//   ICMP SNAT
ip1[1] -> icmp_snat -> Queue -> td2;
//   Other IP → drop
ip1[2] -> Discard;
// Other L2 → drop
eth1[2] -> Discard;



// Topology on inferencing-zone side (napt-eth2)
fd2 \
    -> inCnt2 \
    -> eth2::Classifier(12/0x0806, 12/0x0800, -)  // ARP, IPv4, others
// ARP
eth2[0] -> inf_arp_responder -> Queue -> td2;
// IP
eth2[1] -> ip2::Classifier(14/tcp, 14/icmp, -);
//   TCP DNAT
ip2[0] -> dnat -> Queue -> td1;
//   ICMP DNAT
ip2[1] -> icmp_dnat -> Queue -> td1;
//   Other IP → drop
ip2[2] -> Discard;
// Other L2 → drop
eth2[2] -> Discard;



// Print something on exit
// DriverManager will listen on router's events
// The pause instruction will wait until the process terminates
// Then the prints will run an Click will exit
DriverManager(
    print "Router starting",
    pause,
    print "Packets on ${PORT1}: $(inCnt1.count)",
    print "Packets on ${PORT2}: $(inCnt2.count)",
)
