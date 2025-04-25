/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                /*User */
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }


    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.IPV4         :   parse_ipv4;
            default : accept;
        }
    }

/*
    state parse_INT {
        packet.extract(hdr.INT);
        transition parse_ipv4;
    }
*/

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            // 2  : parse_igmp;
            6   : parse_tcp;
            17  : parse_udp;
            1  : accept;
            default : accept;
        }
    }


    state parse_tcp {
        packet.extract(hdr.tcp);

        meta.ipv4_srcPort = hdr.tcp.srcPort;
        meta.ipv4_dstPort = hdr.tcp.dstPort;

        transition select(hdr.tcp.MIH_fg) {
            0       : parse_SFH_of_TCP;
            1       : parse_MIH;
            default : accept;
        }
    }

    state parse_SFH_of_TCP {
        transition select(hdr.tcp.SFH_fg){
            0 : accept;
            1 : parse_SFH;
            default : accept;
        }
    }


    state parse_udp {
        packet.extract(hdr.udp);

        meta.ipv4_srcPort = hdr.udp.srcPort;
        meta.ipv4_dstPort = hdr.udp.dstPort;

        transition accept;
    }

    // udp only
    state parse_flag {
        packet.extract(hdr.flag);
        transition select(hdr.flag.flag) {
            12      : parse_MIH;
            8       : parse_MIH;
            3       : parse_SFH;
            2       : parse_SFH;
            default : accept;
        }
    }


    state parse_MIH {
        packet.extract(hdr.MIH);
        transition accept;
    }

    state parse_SFH {
        packet.extract(hdr.SFH);
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/


control MyDeparser(packet_out packet, in headers hdr) {
        apply {
            packet.emit(hdr.ethernet);
            packet.emit(hdr.CPU);
            packet.emit(hdr.ipv4);
            packet.emit(hdr.tcp);
            packet.emit(hdr.udp);
            packet.emit(hdr.flag);
            packet.emit(hdr.MIH);
            packet.emit(hdr.SFH);
    }
}

