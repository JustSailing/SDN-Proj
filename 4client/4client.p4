#include <core.p4>
#include <v1model.p4>
const bit<8> UDP_PROTOCOL = 0x11;
const bit<16> TYPE_MESS = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> UPDATE = 0;
const bit<8> READ = 1;
const bit<8> WRITE = 2;
const bit<8> COMPLETED = 3;
const bit<8> ERROR = 4;
const bit<8> UPDATE_MULT = 5;

#define WIDTH_PORT_NUMBER 9

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

//struct metadata_t{}

header ethernet_t{
    macAddr_t dst;
    macAddr_t src;
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
struct metadata_t {
    bit<9> egress_spec;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}


header mess_t{
    bit<16> prot;
    bit<8> msg_id;
    bit<8> type;
    bit<128> uuid;
    bit<32> txt_blk_idx;
    bit<32> len_txt;
    bit<32> time;
    bit<32> start_idx;
    bit<32> end_idx;
    bit<128> node_prev;
    bit<128> node_next;
}


struct headers {
    ethernet_t eth;
    mess_t mess;
    ipv4_t ipv4;
    udp_t udp;
}

error{IPHeaderTooShort}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    state start{
        transition parse_ethernet;
    }

    state parse_ethernet{
        packet.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            TYPE_MESS: parse_mess;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition accept;
    }



    state parse_mess{
        packet.extract(hdr.mess);
        transition select(hdr.mess.prot) {
            TYPE_IPV4 : parse_ipv4;
            default: accept;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata_t meta) {
    apply{}
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    action clone_pkt() {
        const bit<32> ses = 3;
        //const bit<32> idk = 0;
        clone(CloneType.I2E, ses);
    }


    action mac_forward_set_egress(bit<WIDTH_PORT_NUMBER> port) {
        meta.egress_spec = port;
        standard_metadata.egress_spec = port;
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
        //hdr.eth.src = hdr.eth.dst;
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


    apply{
        if (hdr.eth.isValid()) {
            // clone_pkt();
            if(hdr.mess.msg_id == UPDATE_MULT){
                 standard_metadata.mcast_grp = 113;
            }
            if(next_hop_arp_lookup.apply().hit){
                if(mac_forwarding.apply().hit){
                    clone_pkt();
                    return;
                }

            }
            mark_to_drop(standard_metadata);
         }
    }
}



/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    bit<32> temp = 0;
    action port_check(bit<32> dst) {
        temp = dst;
    }

    table port_lookup {
        key = {
                standard_metadata.egress_port: exact;
            }
            actions = {
                port_check;
                NoAction;
            }
    }
    apply{
        if(hdr.mess.msg_id != UPDATE_MULT){
           return;
        }
        port_lookup.apply();
        if(temp != hdr.ipv4.dst){
           return;
        }
        mark_to_drop(standard_metadata);
    }

}


control MyComputeChecksum(inout headers hdr, inout metadata_t meta) {
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
            hdr.ipv4.src,
            hdr.ipv4.dst},
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply{
        packet.emit(hdr.eth);
        packet.emit(hdr.mess);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
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



                                                           


