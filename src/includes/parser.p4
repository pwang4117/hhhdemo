#ifndef _PARSER_P4_
#define _PARSER_P4_

#include <core.p4>

#include "headers.p4"
#include "metadata.p4"

#define ETHERTYPE_IPV4 16w0x0800

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("parse_ipv4") state parse_ipv4 {
        packet.extract<ipv4_t>(hdr.ipv4);
        transition accept;
    }
    @name("start") state start {
        packet.extract<ethernet_t>(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
}

control verifyChecksum(inout headers hdr,
                       inout metadata meta)
{
    apply {
        // There is code similar to this in Github repo p4lang/p4c in
        // file testdata/p4_16_samples/flowlet_switching-bmv2.p4
        // However in that file it is only for a fixed length IPv4
        // header with no options.
        verify_checksum(true,
            { hdr.ipv4.version,
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
            },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

#endif /* _PARSER_P4_ */
