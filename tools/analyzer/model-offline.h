#ifndef MODEL_OFFLINE_H_
#define MODEL_OFFLINE_H_

#include <map>
#include <set>

#include "model.h"

using namespace std;

struct tNodeOffline {
    bool hh = false;
    bool hhh = false;
    uint64_t hhvalue = 0;
    uint64_t hhhvalue = 0;
    set<tPrefix> filter;
};

struct tModelOffline : public tModel {

    uint64_t timeout = 0;
    uint64_t threshold = 10000;
    double quotient = 0.0;
    unsigned firstlen = 16;
    unsigned lastlen = 32;
    bool pureheavy = false;
    bool bytes = true;
    bool flows = false;
    bool reports = false;
    bool collapseacc = false;
    bool firstshot = false;

    uint64_t timestamp = 0;
    uint64_t pcktscounter = 0;
    uint64_t bytescounter = 0;
    set<tPrefix> flowscounter;
    map<tPrefix,tNodeOffline> tree;

    virtual bool processPacket(tPacket &pkt) override {
        if (timeout != 0 && timestamp != 0 && timestamp <= pkt.timestamp) {
            if (firstshot) return false;
            flush(); clear();
            timestamp += timeout;
        }

        pcktscounter += 1;
        bytescounter += pkt.length;
        flowscounter.insert(pkt.dstPrefix);

        if (timestamp == 0) {
            timestamp = pkt.timestamp + timeout;
            cout << "start: " << pkt.timestamp << endl;
        }

        tPrefix prefix = pkt.srcPrefix/lastlen;
        auto it = tree.find(prefix);
        if (it == tree.end()) {
            it = tree.insert(pair<tPrefix,tNodeOffline>(prefix, tNodeOffline())).first;
        }

        if (flows) {
            it->second.filter.insert(pkt.dstPrefix);
            it->second.hhhvalue = it->second.filter.size();
        } else {
            it->second.hhvalue += bytes ? pkt.length : 1;
            it->second.hhhvalue += bytes ? pkt.length : 1;
        }

        return true;
    }

    virtual void clear() override {
        pcktscounter = 0;
        bytescounter = 0;
        flowscounter.clear();
        tree.clear();
    }

    virtual void flush() override {
        if (quotient != 0.0) {
            if (flows) threshold = quotient * flowscounter.size();
            else if (bytes) threshold = quotient * bytescounter;
            else threshold = quotient * pcktscounter;
        }

        // Build hierarchy
        for (auto it = tree.rbegin(); it != tree.rend(); it++) {
            it->second.hh = it->second.hhvalue >= threshold;
            it->second.hhh = it->second.hhhvalue >= threshold;

            if (it->first.length > firstlen) {
                tNodeOffline node; tPrefix prefix = it->first;
                prefix.length -= 1; prefix.norm();

                auto par = tree.find(prefix);
                if (par == tree.end()) {
                    par = tree.insert(pair<tPrefix,tNodeOffline>(prefix, node)).first;
                }

                if (flows) {
                    if (!it->second.hhh) {
                        par->second.filter.insert(it->second.filter.begin(), it->second.filter.end());
                        par->second.hhhvalue = par->second.filter.size();
                    }
                } else {
                    par->second.hhvalue += it->second.hhvalue;
                    if (!it->second.hhh) par->second.hhhvalue += it->second.hhhvalue;
                }
            }
        }

        // Hierarchy heavy-hitters list
        for (auto it = tree.begin(); it != tree.end(); it++) {
            if (!it->second.hhh) continue;
            cout << "timestamp: " << timestamp << ", hhh: 1, prefix: " << it->first.str() << ", value: " << it->second.hhhvalue << endl;
        }

        // Heavy-hitters list
        if (pureheavy) {
            for (auto it = tree.begin(); it != tree.end(); it++) {
                if (!it->second.hh) continue;
                cout << "timestamp: " << timestamp << ", hhh: 0, prefix: " << it->first.str() << ", value: " << it->second.hhvalue << endl;
            }
        }

        // Report counters
        if (reports) {
            for (auto it = tree.begin(); it != tree.end(); it++) {
                if (it->first.length != 32) continue;
                cout << "timestamp," << timestamp << ",report,prefix," << it->first.str() << ",value," << it->second.hhvalue << endl;
            }
        }

        // Print time window stats
        cout << "bytes counter: " << bytescounter << endl;
        if (timeout != 0) cout << "bytes speed: " << (double) bytescounter / (timeout / 1000000) << endl;
        cout << "packets counter: " << pcktscounter << endl;
        if (timeout != 0) cout << "packets speed: " << (double) pcktscounter / (timeout / 1000000) << endl;
        cout << "flows counter: " << flowscounter.size() << endl;
        if (timeout != 0) cout << "flows speed: " << (double) flowscounter.size() / (timeout / 1000000) << endl;
        if (quotient != 0.0) cout << "threshold: " << threshold << endl;
    }
};

#endif
