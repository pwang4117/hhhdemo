#ifndef TRACE_H_
#define TRACE_H_

#include <string>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ether.h>

#include "model.h"

using namespace std;

class tTrace {
    public:
        virtual bool nextPacket(tPacket &pkt) = 0;
        virtual ~tTrace() {};
};

class tTraceData : public tTrace {
    public:
        tTraceData(const char *filename, bool write = false, bool csv = false);
        virtual bool nextPacket(tPacket &pkt);
        bool savePacket(const tPacket &pkt);
        ~tTraceData();

    private:
        ifstream _ifile;
        ofstream _ofile;
        uint64_t _counter = 0;
        bool _write = false;
        bool _csv = false;
};

tTraceData::tTraceData(const char *filename, bool write, bool csv) {
    if ((_write = write)) {
        _ofile.open(filename, (_csv = csv) ? ios_base::out : ofstream::binary);
        if (!_ofile) throw runtime_error("Opening file for writing failed!");
    } else {
        _ifile.open(filename, ifstream::binary);
        if (!_ofile) throw runtime_error("Opening file for reading failed!");
    }
}

tTraceData::~tTraceData() {
    if (_write) {
        _ofile.close();
    } else {
        _ifile.close();
    }
}

bool tTraceData::nextPacket(tPacket &pkt) {
    _ifile.read((char*) &pkt, sizeof(tPacket));
    if (!_ifile) return false;
    _counter++;
    return true;
}

bool tTraceData::savePacket(const tPacket &pkt) {
    if (_csv) {
        _ofile << pkt.srcPrefix.str(false) << ","; // SrcIP
        _ofile << "0.0.0.0" << ","; // DstIP
        _ofile << "0" << ","; // Protocol
        _ofile << "0" << ","; // SrcPort
        _ofile << "0" << endl; // DstPort
        if (!_ofile) return false;
        _counter++;
        return true;
    }

    _ofile.write((const char*) &pkt, sizeof(tPacket));
    if (!_ofile) return false;
    _counter++;
    return true;
}

#ifndef NOPCAP
#include <pcap/pcap.h>

class tTraceFile : public tTrace {
    public:
        tTraceFile(const char *filename);
        virtual bool nextPacket(tPacket &pkt);
        ~tTraceFile();

    private:
        uint64_t _counter = 0;
        pcap_t *_pcap = nullptr;
        int _linktype = DLT_NULL;
        inline bool _parsePacket(tPacket &pkt, const unsigned char *data, unsigned len);
        inline bool _parseEthernet(tPacket &pkt, const unsigned char *data, unsigned len);
        inline bool _parseVlan(tPacket &pkt, const unsigned char *data, unsigned len);
        inline bool _parseIPv4(tPacket &pkt, const unsigned char *data, unsigned len);
        inline bool _parseIPv6(tPacket &pkt, const unsigned char *data, unsigned len);
};

tTraceFile::tTraceFile(const char *filename) {
    char errbuff[PCAP_ERRBUF_SIZE];
    _pcap = pcap_open_offline(filename, errbuff);
    if (!_pcap) throw runtime_error(errbuff);
    _linktype = pcap_datalink(_pcap);
}

tTraceFile::~tTraceFile() {
    if (_pcap) pcap_close(_pcap);
}

bool tTraceFile::nextPacket(tPacket &pkt) {
    struct pcap_pkthdr *pkthdr;
    const unsigned char *pktdata;
    while (true) {
        int retval = pcap_next_ex(_pcap, &pkthdr, &pktdata);
        if (retval == -2) return false;
        if (retval <= 0) throw runtime_error(pcap_geterr(_pcap));

        _counter++;
        if (!_parsePacket(pkt, pktdata, pkthdr->caplen)) {
            cout << "packet no. " << _counter << " damaged, skipping!" << endl;
            //throw runtime_error("packet parsing failed");
            continue;
        }

        pkt.timestamp = 1000000*pkthdr->ts.tv_sec + pkthdr->ts.tv_usec;
        pkt.length = pkthdr->len; // TODO: která vrstva
        return true;
    }
}

inline bool tTraceFile::_parsePacket(tPacket &pkt, const unsigned char *data, unsigned len) {
    if (_linktype == DLT_EN10MB) return _parseEthernet(pkt, data, len);
    else if (_linktype == DLT_RAW) {
        if (!len) { return false; }
        if (*data >> 4 == 4) return _parseIPv4(pkt, data, len);
        if (*data >> 4 == 6) return _parseIPv6(pkt, data, len);
        return false;
    }
    return false;
}

inline bool tTraceFile::_parseEthernet(tPacket &pkt, const unsigned char *data, unsigned len) {
    if (len < ETH_HLEN) return false;
    struct ether_header *ether = (struct ether_header *) data;
    data += ETH_HLEN; len -= ETH_HLEN;
    switch (be16toh(ether->ether_type)) {
        case ETHERTYPE_IP:
            return _parseIPv4(pkt, data, len);
        case ETHERTYPE_IPV6:
            return _parseIPv6(pkt, data, len);
        case ETHERTYPE_VLAN:
            return _parseVlan(pkt, data, len);
        default:
            return false;
    }
}

struct vlan_header {
    uint16_t id;
    uint16_t ether_type;
} __attribute__((__packed__));

#define VLAN_HLEN sizeof(struct vlan_header)

inline bool tTraceFile::_parseVlan(tPacket &pkt, const unsigned char *data, unsigned len) {
    while (len >= VLAN_HLEN) {
        struct vlan_header *vlan = (struct vlan_header *) data;
        data += VLAN_HLEN; len -= VLAN_HLEN;
        switch (be16toh(vlan->ether_type)) {
            case ETHERTYPE_IP:
                return _parseIPv4(pkt, data, len);
            case ETHERTYPE_IPV6:
                return _parseIPv6(pkt, data, len);
            case ETHERTYPE_VLAN:
                continue;
            default:
                return false;
        }
    }
    return false;
}

inline bool tTraceFile::_parseIPv4(tPacket &pkt, const unsigned char *data, unsigned len) {
    if (!len) return false;
    struct ip *ip_header = (struct ip *) data;
    if (ip_header->ip_v != 4) { return false; }
    unsigned ip_hlen = ip_header->ip_hl << 2;
    if (len < ip_hlen) { return false; }
    data += ip_hlen; len -= ip_hlen;
    pkt.srcPrefix.set((const unsigned char *) &(ip_header->ip_src));
    pkt.dstPrefix.set((const unsigned char *) &(ip_header->ip_dst));
    pkt.ipver = 4;
    return true;
}

inline bool tTraceFile::_parseIPv6(tPacket &pkt, const unsigned char *data, unsigned len) {
    const unsigned IP6_HLEN = 40;
    if (len < IP6_HLEN) { return false; }
    struct ip6_hdr *ip_header = (struct ip6_hdr *) data;
    if ((ip_header->ip6_vfc >> 4) != 6) { return false; }
    data += IP6_HLEN; len -= IP6_HLEN;
    //pkt.srcPrefix6.set((const unsigned char *) &(ip_header->ip6_src));
    //pkt.dstPrefix6.set((const unsigned char *) &(ip_header->ip6_dst));
    pkt.ipver = 6;
    return true;
}

#endif // NOPCAP

#endif