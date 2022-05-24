#ifndef MODEL_HASH_H_
#define MODEL_HASH_H_

#include <map>
#include <cmath>
#include <vector>
#include <cassert>

#include "model.h"
#include "bloom-filter.h"

using namespace std;

struct tNodeHash {
    tPrefix prefix;
    bool valid = false;
    uint64_t timestamp = 0;
    uint64_t childvals[2] = {0, 0};
    uint64_t summaryval = 0;

    tNodeHash() = default;
    tNodeHash(tPrefix pref): prefix(pref), valid(true) {}
};

struct tModelHash : public tModel {
    uint64_t timestamp = 0;
    uint64_t atimeout = 20000000; // 20s
    uint64_t itimeout = 60000000; // 1min
    uint64_t threshold = 10000;
    uint64_t memory = 0;
    uint64_t speed = 0;
    unsigned firstlen = 16;
    unsigned lastlen = 32;
    double filter_false_positive_probability = 0.1;
    unsigned long long filter_maximum_size = 10000000;
    unsigned long long filter_projected_element_count = 100000;
    bool pureheavy = false;
    bool newinvalidation = false;
    bool collapseacc = false;
    bool bytes = true;
    bool flows = false;
    bool reports = false;
    bool hashcopt = true;
    bool hashadapt = false;
    bool hashskip = false;
    uint64_t div = 0;

    uint64_t collisions = 0;

    vector<uint64_t> atimeouts;
    vector<uint64_t> memsizes;
    vector<uint64_t> thresholds;

    vector<vector<bloom_filter>> filters;
    vector<uint64_t> filterstamps;

    vector<vector<tNodeHash>> table;

    void init(uint64_t divider) {
        div = divider;

        if (flows) {
            filters.resize(lastlen-firstlen+1);
            filterstamps.resize(lastlen-firstlen+1, 0);

            bloom_parameters params;
            // How many elements roughly do we expect to insert?
            params.projected_element_count = filter_projected_element_count;
            // Maximum tolerable false positive probability? (0,1)
            params.false_positive_probability = filter_false_positive_probability;
            // Compute optimal parameters
            params.compute_optimal_parameters();
            // Save optimal parameters
            unsigned int optim_hashes = params.optimal_parameters.number_of_hashes;
            unsigned long long int optim_size = params.optimal_parameters.table_size;
            // Set maximum table size
            params.maximum_size = filter_maximum_size;
            // Compute optimal parameters again
            params.compute_optimal_parameters();

            cout << "bloom-filter: ";
            cout << params.optimal_parameters.number_of_hashes << " (" << optim_hashes << "), ";
            cout << params.optimal_parameters.table_size << " (" << optim_size << ")" << endl;

            // Instantiate Bloom Filter as a blueprint
            bloom_filter filter(params);

            for (unsigned i = lastlen-1; i >= firstlen; i--) {
                filters[lastlen-i].resize(2, filter);
                if (divider == 0) break;
            }
        }

        if (speed == 0) return;
        threshold = speed * atimeout / 1000000;

        atimeouts.push_back(atimeout);
        thresholds.push_back(threshold);

        uint64_t memcoef = log2(memory/(lastlen-firstlen+1));
        uint64_t memchun = (memory-((1UL << (memcoef+1))-2))/(lastlen-memcoef-firstlen+1);
        uint64_t memrest = (memory-((1UL << (memcoef+1))-2))%(lastlen-memcoef-firstlen+1);

        table.resize(lastlen-firstlen+1);

        uint64_t memsize = memchun;
        if (memrest > 0) { memsize++; memrest--; }
        memsizes.push_back(memsize);
        table[0].resize(memsize);

        for (unsigned i = lastlen-1; i >= firstlen; i--) {

            if (divider > 0) {
                double coeff = (double)(lastlen-i)/divider;
                uint64_t win = (coeff <= 1) ? atimeout : atimeout/coeff;
                uint64_t thr = speed * win / 1000000;
                atimeouts.push_back(win);
                thresholds.push_back(thr);
            } else {
                atimeouts.push_back(atimeout);
                thresholds.push_back(threshold);
            }

            uint64_t memsize = (1UL << i) <= memchun ? (1UL << i) : memchun;
            if (memrest > 0) { memsize++; memrest--; }
            memsizes.push_back(memsize);
            table[lastlen-i].resize(memsize);
        }

        for (unsigned i = 0; i < atimeouts.size(); i++) {
            cout << i << ": " << atimeouts[i] << ", " << thresholds[i] << ", " << memsizes[i] << endl;
        }
    }

    uint64_t getAtimeout(unsigned len) {
        unsigned index = lastlen-len;
        if (index >= atimeouts.size())
            return atimeout;
        return atimeouts[index];
    }

    uint64_t getThreshold(unsigned len) {
        unsigned index = lastlen-len;
        if (index >= thresholds.size())
            return threshold;
        return thresholds[index];
    }

    uint64_t getMemsize(unsigned len) {
        assert(lastlen-len < 32);
        unsigned index = lastlen-len;
        if (index >= memsizes.size()) {
            cerr << len << endl;
            cerr << index << endl;
            cerr << memsizes.size() << endl;
            assert(false);
            return 0;
        }
        return memsizes[index];
    }

    void filter(unsigned &cincrement, unsigned &sincrement, const tPacket &pkt, const tPrefix &currpref, unsigned currlen, bool child) {
        int index = (div > 0) ? lastlen-currlen : 1;
        vector<bloom_filter> &filter = filters[index];
        uint64_t &filterstamp = filterstamps[index];

        // Filter invalid?
        if (filterstamp + getAtimeout(currlen) <= pkt.timestamp) {
            filterstamp += getAtimeout(currlen);
            if (filterstamp + getAtimeout(currlen) <= pkt.timestamp)
                filterstamp = pkt.timestamp;
            filter[0].clear();
            filter[1].clear();
        }

        struct TFilterKey {
            unsigned srcPrefix;
            unsigned dstPrefix;
        };

        TFilterKey filterKey;
        filterKey.srcPrefix = currpref.prefix;
        filterKey.dstPrefix = pkt.dstPrefix.prefix;

        bool left = filter[0].contains(filterKey);
        bool right = filter[1].contains(filterKey);

        // Check children flags
        if (left || right) sincrement = 0;
        if (left && !child) cincrement = 0;
        if (right && child) cincrement = 0;

        // Update filter
        filter[child].insert(filterKey);
    }

    virtual bool processPacket(tPacket &pkt) override {

        if (timestamp == 0) {
            timestamp = pkt.timestamp + itimeout;
            cout << "start: " << pkt.timestamp << endl;
        }

//        cout << pkt.srcPrefix.str() << endl;
//        cout << table.size() << endl;

        tPrefix currpref; tNodeHash *currptr;
        unsigned curridx, currlen = firstlen;

        // Lookup a valid prefix
        for (unsigned len = lastlen; len >= firstlen; len--) {
            currpref = pkt.srcPrefix/len;
            curridx = tHash::hash32(currpref, getMemsize(len));

//            cout << endl;
//            cout << len << endl;
//            cout << currpref.str() << endl;
//            cout << getMemsize(len) << endl;
//            cout << curridx << endl;

            currptr = &(table[lastlen-len][curridx]);
            if ((newinvalidation && currptr->valid) || (!newinvalidation && currptr->timestamp + itimeout > pkt.timestamp)) {
                currlen = len;
                if (hashadapt && !(currptr->prefix == currpref)) {
                    currptr = nullptr; continue;
                }
                if (!hashcopt) break;
                for (unsigned l = len; l >= firstlen; l--) {
                    tPrefix temppref = pkt.srcPrefix/l;
                    unsigned tempidx = tHash::hash32(temppref, getMemsize(l));
                    if (table[lastlen-l][tempidx].prefix[l-1] != temppref[l-1]) {
                        currptr = nullptr; break;
                    }
                }
                if (currptr != nullptr) break;
            } else {
                currptr = nullptr;
            }
        }

        // Not found, insert new node as the root
        if (currptr == nullptr) {
            curridx = tHash::hash32(currpref, getMemsize(firstlen));
            currptr = &(table[lastlen-firstlen][curridx] = tNodeHash(currpref));
            currptr->timestamp = pkt.timestamp;
        }

        // Report collision
        if (!(currptr->prefix == currpref)) {
            collisions++;
//            cout << "COLLISION !!! " << currptr->prefix.str() << " " << currpref.str() << endl;
//
//            for (unsigned l = currlen-1; l >= firstlen; l--) {
//                cout << currlen << ": ";
//                tPrefix temppref = pkt.srcPrefix/l;
//                unsigned tempidx = tHash::hash32(temppref, getMemsize(l));
//                cout << table[lastlen-l][tempidx].prefix.str() << " " << temppref.str() << " ";
//                cout << ((int) table[lastlen-l][tempidx].prefix[l-1] != temppref[l-1]) << endl;
////                if (table[lastlen-l][tempidx].prefix[l-1] != temppref[l-1]) {
////                    currptr = nullptr; break;
////                }
//            }
//
//            cout << tHash::hash32(currpref, getMemsize(currlen)) << endl;
//            cout << tHash::hash32(currptr->prefix, getMemsize(currlen)) << endl;
//
//            assert(false);
        }

        // Handle relative prefixes lengths
        unsigned nextlen = currlen+1;
        unsigned prevlen = currlen-1;
        if (currlen == firstlen) prevlen = firstlen;
        if (currlen == lastlen) nextlen = lastlen;

        // Create shortcuts
        tNodeHash &currnode = *currptr;
        bool currchild = pkt.srcPrefix[currlen];
        tPrefix prevpref = pkt.srcPrefix/prevlen;
        tPrefix nextpref = pkt.srcPrefix/nextlen;

        // Define increments, according mode
        unsigned cincrement = (bytes && !flows) ? pkt.length : 1;
        unsigned sincrement = cincrement;

        // Collison detected? Skip and do nothing :-)
        if (hashskip && !(currptr->prefix == currpref)) {

        // Prefix node inactive timeout (invalidation)?
        } else if (newinvalidation && currnode.timestamp + itimeout <= pkt.timestamp) {

            // Report invalidation
            if (reports)
                cout << "timestamp: " << pkt.timestamp << ", event: invalid, prefix_found: " << currpref.str() << ", value: " << currnode.summaryval << endl;

            // Erase (invalidate) current prefix node
            currptr->timestamp = 0;
            currptr->valid = false;

        // Prefix node (active) timeout?
        } else if (currnode.timestamp + getAtimeout(currlen) <= pkt.timestamp) {

            // Keep the rule?
            if (currnode.summaryval >= getThreshold(currlen)) {

                // Report hierarchical Heavy-Hitter
                cout << "timestamp: " << pkt.timestamp << ", event: hhh, prefix_found: " << currpref.str() << ", value: " << currnode.summaryval << endl;

                // Reset current prefix node
                currnode = tNodeHash(currpref);
                if (flows) filter(cincrement, sincrement, pkt, currpref, currlen, currchild);
                currnode.childvals[currchild] = cincrement;
                currnode.summaryval = sincrement;
                currnode.timestamp = pkt.timestamp;

            // Collapse rule?
            } else {

                // Report collapsing
                if (reports)
                    cout << "timestamp: " << pkt.timestamp << ", event: collapse, prefix_found: " << currpref.str() << ", value: " << currnode.summaryval << endl;

                // Erase (invalidate) current prefix node
                currptr->timestamp = 0;
                currptr->valid = false;

                // Insert a new prefix node
                bool prevchild = pkt.srcPrefix[prevlen];
                tNodeHash &prevnode = table[lastlen-prevlen][tHash::hash32(prevpref, getMemsize(prevlen))] = tNodeHash(prevpref);
                if (flows) filter(cincrement, sincrement, pkt, prevpref, prevlen, prevchild);
                prevnode.childvals[prevchild] = cincrement;
                prevnode.summaryval = sincrement;
                prevnode.timestamp = pkt.timestamp;
            }

        // Expand rule?
        } else if (currnode.childvals[currchild] >= getThreshold(currlen) && currlen != lastlen) {

            // Report pure Heavy-Hitter
            if (pureheavy || reports)
                cout << "timestamp: " << pkt.timestamp << ", event: expand, prefix_found: " << nextpref.str() << ", value: " << currnode.summaryval << endl;

            // Subtract HH value from current prefix node
            currnode.childvals[currchild] = 0;
            currnode.summaryval = currnode.childvals[!currchild];

            // Insert a new prefix node
            bool nextchild = pkt.srcPrefix[nextlen];
            tNodeHash &nextnode = table[lastlen-nextlen][tHash::hash32(nextpref, getMemsize(nextlen))] = tNodeHash(nextpref);
            if (flows) filter(cincrement, sincrement, pkt, nextpref, nextlen, nextchild);
            nextnode.childvals[nextchild] = cincrement;
            nextnode.summaryval = sincrement;
            nextnode.timestamp = pkt.timestamp;

        // Basic update
        } else {
            if (flows) filter(cincrement, sincrement, pkt, currpref, currlen, currchild);
            currnode.childvals[currchild] += cincrement;
            currnode.summaryval += sincrement;
        }

        return true;
    }

    virtual void clear() override {
    }

    virtual void flush() override {
        cout << "collisions: " << collisions << endl;
    }
};

#endif
