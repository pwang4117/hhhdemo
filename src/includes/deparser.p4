#ifndef _DEPARSER_P4_
#define _DEPARSER_P4_

#include <core.p4>

#include "headers.p4"
#include "metadata.p4"

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit<ethernet_t>(hdr.ethernet);
        packet.emit<ipv4_t>(hdr.ipv4);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
       update_checksum(true, { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
#ifdef ALLOW_IPV4_OPTIONS
                , hdr.ipv4.options
#endif /* ALLOW_IPV4_OPTIONS */
            }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);    
    }
}

#endif /* _DEPARSER_P4_ */
