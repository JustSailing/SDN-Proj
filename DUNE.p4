#include <core.p4>
#include <v1model.p4>

const bit<8> UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> IPV4_OPTION_R_SERVER = 0x2020;
const bit<8> UPDATE = 0;
const bit<8> READ = 1;
const bit<8> WRITE = 2;
const bit<8> REGISTER = 3;
const bit<8> GETPERM = 4;
const bit<8> COMPLETED = 5;

typedef bit<8> MessageType;
typedef bit<64> UUID;
typedef bit<16> BlockId;
typedef bit<32> StartIndex;
typedef bit<32> EndIndex;

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t{
        macAddr_t dstAddr;
        macAddr_t srcAddr;
        bit<16>   etherType;
}

header ipv4_t{
        bit<4> version;
        bit<4>    ihl;
        bit<8>    diffserv;
        bit<16>   totalLen;
        bit<16>   identification;
        bit<3>    flags;
        bit<13>   fragOffset;
        bit<8>    ttl;
        bit<8>    protocol;
        bit<16>   hdrChecksum;
        ip4Addr_t src;
        ip4Addr_t dst;
}


header mess_t{
        MessageType ms;
        UUID id;
        BlockId bId;
        StartIndex start;
        EndIndex  end;
}


struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    mess_t mess;
}

error{IPHeaderTooShort}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start{
            transition parse_ethernet;
    }

    state parse_ethernet{
            packet.extract(hdr.ethernet);
            transition select(hdr.ethernet.etherType) {
                IPV4_OPTION_R_SERVER: parse_mess;
                TYPE_IPV4: parse_ipv4;           
                default: accept;
            }
    }

    state parse_ipv4{
            packet.extract(hdr.ipv4);
            verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
            transition select(hdr.ipv4.ihl) {
                5             : accept;
                default       : accept;
            }
    }



    state parse_mess{
            packet.extract(hdr.mess);
            transition select(hdr.mess.mes) {
                0 .. 5 : accept;
                default:  drop();
            }
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply{}
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action clone_pkt() {
        clone_preserving_field_list(CloneType.I2E, 3, 0);
    }

    apply{
        if(hdr.ipv4.isValid()) {
            clone_pkt();
            return;
        }
        // drops packet 
        // drop()
        standard_metadata.drop = true;
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action ros_forward(bit<32> dest) {
        if(dest == 1){
            hdr.ipv4.dst = 0x0a000031;
        }
        else if(dest == 2){
            hdr.ipv4.dst = 0x0a000032;
        }
        else if(dest == 3){
            hdr.ipv4.dst = 0x0a000033;
        }
        else if(dest == 4){
            hdr.ipv4.dst = 0x0a000034;
        }
        else if(dest == 5){
            hdr.ipv4.dest = 0x0a000035;
        }
    }

    table mess_table{
            keys = {
                    hdr.mess.start : range
            }
            actions = {
                ros_forward;
                NoAction;
            }
            const entries = {
                0..10000 : ros_forward(1);
                10001..20000 : ros_forward(2);
                20001..30000 : ros_forward(3);
                30001..40000 : ros_forward(4);
                40001..50000 : ros_forward(5);
            }
            default_action = NoAction();
    }

    action mac_forward_set_egress(bit <WIDTH_PORT_NUMBER> port) {
        meta.egress_spec = port;
    }

    table mac_forwarding{
            key = {
                hdr.eth.dst : exact;
            }
            actions = {
                mac_forward_set_egress;
                NoAction;
            }
    }

    action arp_lookup_set_addresses(bit<48> mac_address) {
        hdr.eth.src = hdr.eth.dst;
        hdr.eth.dst = mac_address;
    }

    table next_hop_arp_lookup{
            key = {
                hdr.ipv4.dst : exact;
            }
            actions = {
                arp_lookup_set_addresses;
                NoAction;
            }
    }

    action monitor_forward() {
        hdr.ipv4.dst = 0x0a000037;
    }
   
    apply{
            if (hdr.eth.isValid()) {
                if(standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE){
                    monitor_forward();
                    if(next_hop_arp_lookup.apply().hit){
                        return;
                    }
                    drop();
                }
                else {
                    if (mess_table.apply().hit) {
                    if(next_hop_arp_lookup.apply().hit){
                        if(mac_forwarding.apply().hit){
                            return;
                        }
                    }
                };
               
            }
            drop();
    }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply{
            update_checksum(
                    hdr.ipv4.isValid(),
                    {hdr.ipv4.version,
                     hdr.ipv4.ihl,
                     hdr.ipv4.diffserv,
                     hdr.ipv4.totalLen,
                     hdr.ipv4.identification,
                     hdr.ipv4.flags,
                     hdr.ipv4.fragOffset,
                     hdr.ipv4.ttl,
                     hdr.ipv4.protocol,
                     hdr.ipv4.srcAddr,
                     hdr.ipv4.dstAddr},
                    hdr.ipv4.hdrChecksum,
                    HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply{
            packet.emit(hdr.ethernet);
            packet.emit(hdr.ipv4);
            //packet.emit(hdr.ipv4_option);
            packet.emit(hdr.mess);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
        MyParser(),
        MyVerifyChecksum(),
        MyIngress(),
        MyEgress(),
        MyComputeChecksum(),
        MyDeparser()

)
main;