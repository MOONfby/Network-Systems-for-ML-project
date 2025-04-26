// 2 variables to hold ports names
define($PORT1 napt-eth1, $PORT2 napt-eth2)
//require(library ./forwarder.click)
//Forwarder($PORT1, $PORT2, $VERBOSE)
// Script will run as soon as the router starts
Script(print "Click NAPT router on $PORT1 $PORT2")

// Group common elements in a single block. $port is a parameter used just to print
elementclass L2Forwarder {$port|
	input
	->cnt::Counter
	->Classifier(
        12/0806, // ARP
        12/0800, // IP
        -        // others
    )
	->output
}

// From where to pick packets
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)

// Where to send packets
td1::ToDevice($PORT1, METHOD LINUX)
td2::ToDevice($PORT2, METHOD LINUX)


// IP Rewriters for NAT and PING
napt_rewriter :: IPRewriter(
    pattern - 10.0.0.0/24 100.0.0.1 40000-50000 - 100.0.0.0/24 10.0.0.1 40000-50000
);
icmp_napt :: ICMPPingRewriter(
    pattern 10.0.0.0/24 100.0.0.1, pattern 100.0.0.0/24 10.0.0.1
);


// ARP Responders
user_arp_responder :: ARPResponder(10.0.0.1 02:00:00:00:00:01);
inf_arp_responder  :: ARPResponder(100.0.0.1 02:00:00:00:00:02);


// Instantiate 2 forwarders, 1 per directions
fd1
-> fwd1::L2Forwarder($PORT1)
fwd1[0] -> user_arp_responder -> Queue -> td1;
fwd1[1] -> IPClassifier(
    tcp,
    icmp,
    -
)
-> MarkIPHeader(0)
-> napt_rewriter
-> Queue
-> td2;

fd2
-> fwd2::L2Forwarder($PORT2)
fwd2[0] -> inf_arp_responder -> Queue -> td2;
fwd2[1] -> IPClassifier(
    tcp,
    icmp,
    -
)
-> MarkIPHeader(0)
-> napt_rewriter
-> Queue
-> td1;


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
