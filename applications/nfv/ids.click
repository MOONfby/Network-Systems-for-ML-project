
fromClientCounter, fromServerCounter, toClientCounter, toServerCounter :: AverageCounter;
clientARPCounter, serverARPCounter, clientIPCounter, serverIPCounter, httpCounter, toInspCounter,
get, put, post, head, options, trace, delete, connect,
clientDropCounter, serverDropCounter :: Counter;


fromClient :: FromDevice(ids-eth1, METHOD LINUX, SNIFFER false);
fromServer :: FromDevice(ids-eth3, METHOD LINUX, SNIFFER false);
toClient :: Queue -> toClientCounter -> ToDevice(ids-eth1, METHOD LINUX);
toServer :: Queue -> toServerCounter -> ToDevice(ids-eth3, METHOD LINUX);
toInspector :: Queue -> toInspCounter -> ToDevice(ids-eth2, METHOD LINUX);

serverTypeClassifier, clientTypeClassifier :: Classifier(12/0806,      //ARP
                                                         12/0800,      //IP
                                                         -);

clientIPClassifier :: Classifier(
                    23/01,       //ICMP packets
					47/02,       //SYN
					47/12,       //SYN ACK
					47/10,       //ACK
					47/04,       //RST
					47/11,       //FIN ACK
					-);

httpClassifier :: Classifier(
					66/474554,                          // GET
					66/504f5354,						// POST
					66/48454144,                        // HEAD
					66/4f5054494f4e53, 					// OPTIONS
					66/5452414345, 						// TRACE
					66/505554,							// PUT
					66/44454c455445, 					// DELETE
					66/434f4e4e454354, 					// CONNECT
					-);

httpInjectionClassifier :: Classifier(
					0/636174202f6574632f706173737764,//cat/etc/passwd
                    0/636174202f7661722f6c6f672f,    //cat/var/log
                    0/494E53455254,                  //INSERT
                    0/555044415445,                  //UPDATE
                    0/44454C455445,                  //DELETE
                    -);

search :: Search("\r\n\r\n")

fromClient -> fromClientCounter -> clientTypeClassifier;
clientTypeClassifier[0] -> clientARPCounter -> toServer;
clientTypeClassifier[1] -> clientIPCounter -> clientIPClassifier;
clientTypeClassifier[2] -> clientDropCounter -> Discard;

clientIPClassifier[0, 1, 2, 3, 4, 5] -> toServer;
clientIPClassifier[6] -> httpCounter -> httpClassifier;

httpClassifier[0] -> get -> toInspector;
httpClassifier[1] -> post -> toServer;
httpClassifier[2] -> head -> toInspector;
httpClassifier[3] -> options -> toInspector;
httpClassifier[4] -> trace -> toInspector;
httpClassifier[5] -> put -> search;
httpClassifier[6] -> delete -> toInspector;
httpClassifier[7] -> connect -> toInspector;
httpClassifier[8] -> toInspector;

search[0] -> httpInjectionClassifier;
search[1] -> toInspector;

httpInjectionClassifier[0, 1, 2, 3, 4] -> UnstripAnno() -> toInspector;
httpInjectionClassifier[5] -> UnstripAnno() -> toServer;


fromServer -> fromServerCounter -> serverTypeClassifier;
serverTypeClassifier[0] -> serverARPCounter -> toClient;
serverTypeClassifier[1] -> serverIPCounter -> toClient;
serverTypeClassifier[2] -> serverDropCounter -> Discard;



DriverManager(wait , print > ../../results/ids.report  "
        =================== IDS Report ===================
        Input Packet Rate (pps): $(add $(fromClientCounter.rate) $(fromServerCounter.rate))
        Output Packet Rate(pps): $(add $(toClientCounter.rate) $(toServerCounter.rate))

        Total # of input packets: $(add $(fromClientCounter.count) $(fromServerCounter.count))
        Total # of output packets: $(add $(toServerCounter.count) $(toClientCounter.count))

        Total # of ARP packets: $(add $(clientARPCounter.count) $(serverARPCounter.count))
        Total # of IP packets: $(add $(clientIPCounter.count) $(serverIPCounter.count))
        Total # of HTTP packets: $(httpCounter.count)

        Total # of HTTP GET packets: $(get.count)
        Total # of HTTP PUT packets: $(put.count)
        Total # of HTTP POST packets: $(post.count)
        Total # of HTTP HEAD packets: $(head.count)
        Total # of HTTP OPTIONS packets: $(options.count)
        Total # of HTTP TRACE packets: $(trace.count)
        Total # of HTTP DELETE packets: $(delete.count)
        Total # of HTTP CONNECT packets: $(connect.count)

        Total # of dropped packets: $(add $(clientDropCounter.count) $(serverDropCounter.count))
        Total # of packets to inspector: $(toInspCounter.count)
        ==================================================
" , stop);