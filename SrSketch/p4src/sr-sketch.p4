/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"


/*CONSTANTS*/
// #define SKETCH_BUCKET_LENGTH 28
// #define SKETCH_CELL_BIT_WIDTH 64

/*
    SKETCH_BUCKET_LENGTH: 一维数组长度
    SKETCH_CELL_BIT_WIDTH： 数组元素宽度
*/
/*
#define SKETCH_REGISTER(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) sketch##num
*/
/*
#define SKETCH_COUNT(num, algorithm) hash(meta.index_sketch##num, HashAlgorithm.algorithm, (bit<16>)0, {hdr.ipv4.src_addr, \
hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.ipv4.protocol}, (bit<32>)SKETCH_BUCKET_LENGTH); \
sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
meta.value_sketch##num = meta.value_sketch##num + 1; \
sketch##num.write(meta.index_sketch##num, meta.value_sketch##num)
*/

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

/*
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}
*/

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(/*USER*/
                inout header    hdr,
                inout metadata  meta,
                inout standard_metadata_t standard_metadata) {
        register<bit<>>

}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(
    /*USER*/
    inout header                hdr,
    inout my_egress_metadata_t  meta,
    inout standard_metadata_t   standard_metadata) {

}


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyIngressParser(),
// MyVerifyChecksum(),
MyIngress(),
MyIngressDeparser(),
MyEgressParser(),
MyEgress(),
// MyComputeChecksum(),
MyEgressDeparser()
) main;