#ifndef MODEL_ONLINE_H_
#define MODEL_ONLINE_H_

#include <map>
#include <vector>
#include <cassert>

#include "model.h"

using namespace std;

struct tNodeOnline {
    uint64_t timestamp = 0;
    uint64_t childvals[2] = {0, 0};
    uint64_t summaryval = 0;
};

struct tModelOnline : public tModel {
    uint64_t timestamp = 0;
    uint64_t atimeout = 20000000; // 20s
    uint64_t itimeout = 60000000; // 1min
    uint64_t repgran = 20000000; // 20s    
    uint64_t threshold = 10000;
    uint64_t speed = 0;
    unsigned firstlen = 16;
    unsigned lastlen = 32;
    bool details = false;
    bool pureheavy = false;
    bool newinvalidation = false;
    bool collapseacc = false;
    bool bytes = true;
    bool flows = false;
    bool reports = false;

    vector<uint64_t> atimeouts;
    vector<uint64_t> thresholds;

    vector<map<tPrefix,map<tPrefix,bool[2]>>> filters;
    vector<uint64_t> filterstamps;

    map<tPrefix,tNodeOnline> tree;

    void init(uint64_t divider) {
        filters.resize(lastlen-firstlen+1);
        filterstamps.resize(lastlen-firstlen+1, 0);

        if (speed == 0) return;
        threshold = speed * atimeout / 1000000;
        if (divider < 1) return;
        atimeouts.push_back(atimeout);
        thresholds.push_back(threshold);

        for (unsigned i = lastlen-1; i >= firstlen; i--) {
            double coeff = (double)(lastlen-i)/divider;
            uint64_t win = (coeff <= 1) ? atimeout : atimeout/coeff;
            uint64_t thr = speed * win / 1000000;
            atimeouts.push_back(win);
            thresholds.push_back(thr);
        }

        for (unsigned i = 0; i < atimeouts.size(); i++) {
            cout << i << ": " << atimeouts[i] << ", " << thresholds[i] << endl;
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

    void filter(unsigned &cincrement, unsigned &sincrement, const tPacket &pkt, const tPrefix &currpref, unsigned currlen, bool child) {
        map<tPrefix,map<tPrefix,bool[2]>> &filter = filters[lastlen-currlen];
        uint64_t &filterstamp = filterstamps[lastlen-currlen];

        // Filter invalid?
        if (filterstamp + getAtimeout(currlen) <= pkt.timestamp) {
            filterstamp += getAtimeout(currlen);
            if (filterstamp + getAtimeout(currlen) <= pkt.timestamp)
                filterstamp = pkt.timestamp;

            //uint64_t uniquesrcdst = 0;
            //cout << "filter: layer " << (lastlen-currlen) << ", ";
            //for (auto it = filter.begin(); it != filter.end(); it++) {
            //    uniquesrcdst += it->second.size();
            //} cout << "count: " << uniquesrcdst << endl;

            filter.clear();
        }

        // Get destination IP filter
        map<tPrefix,bool[2]> &dstfilter = filter[currpref];
        auto *flags = dstfilter[pkt.dstPrefix];

        //cout << (int) flags[0] << (int) flags[1] << endl;

        // Check children flags
        if (flags[0] || flags[1]) sincrement = 0;
        if (flags[child]) cincrement = 0;

        // Update filter
        flags[child] = true;
    }

    virtual bool processPacket(tPacket &pkt) override {

        if (timestamp == 0) {
            timestamp = pkt.timestamp + repgran;
            cout << "start: " << pkt.timestamp << endl;
        }

        map<tPrefix,tNodeOnline>::iterator currit;
        tPrefix currpref; unsigned currlen = firstlen;

        // Lookup a valid prefix
        for (unsigned len = lastlen; len >= firstlen; len--) {
            currpref = pkt.srcPrefix/len;
            currit = tree.find(currpref);
            if (currit != tree.end()) {
                if (newinvalidation || currit->second.timestamp + itimeout > pkt.timestamp) {
                    currlen = len; break;
                } else {
                    tree.erase(currit);
                    currit = tree.end();
                }
            }
        }

        // Not found, insert new node as the root
        if (currit == tree.end()) {
            currit = tree.insert(pair<tPrefix,tNodeOnline>(currpref, tNodeOnline())).first;
            currit->second.timestamp = pkt.timestamp;
        }

        // Handle relative prefixes lengths
        unsigned nextlen = currlen+1;
        unsigned prevlen = currlen-1;
        if (currlen == firstlen) prevlen = firstlen;
        if (currlen == lastlen) nextlen = lastlen;

        // Create shortcuts
        tNodeOnline &currnode = currit->second;
        bool currchild = pkt.srcPrefix[currlen];
        tPrefix prevpref = pkt.srcPrefix/prevlen;
        tPrefix nextpref = pkt.srcPrefix/nextlen;

        // Define increments, according mode
        unsigned cincrement = (bytes && !flows) ? pkt.length : 1;
        unsigned sincrement = cincrement;

        // Prefix node inactive timeout (invalidation)?
        if (newinvalidation && currnode.timestamp + itimeout <= pkt.timestamp) {

            // Report invalidation
            if (reports)
                cout << "timestamp: " << pkt.timestamp << ", event: invalid, prefix_found: " << currpref.str() << ", value: " << currnode.summaryval << endl;

            // Erase current prefix node
            tree.erase(currit);

        // Prefix node (active) timeout?
        } else if (currnode.timestamp + getAtimeout(currlen) <= pkt.timestamp) {

            // Keep the rule?
            if (currnode.summaryval >= getThreshold(currlen)) {

                // Report hierarchical Heavy-Hitter
                cout << "timestamp: " << pkt.timestamp << ", event: hhh, prefix_found: " << currpref.str() << ", value: " << currnode.summaryval << endl;

                // Reset current prefix node
                currnode = tNodeOnline();
                if (flows) filter(cincrement, sincrement, pkt, currpref, currlen, currchild);
                currnode.childvals[currchild] = cincrement;
                currnode.summaryval = sincrement;
                currnode.timestamp = pkt.timestamp;

            // Collapse rule?
            } else {

                // Erase current prefix node
                tree.erase(currit);

                // Report collapsing
                if (reports) {
                    if (tree.find(prevpref) == tree.end()) {
                        cout << "timestamp: " << pkt.timestamp << ", event: move, prefix_found: " << currpref.str() << ", value: " << currnode.summaryval << endl;
                    } else {
                        cout << "timestamp: " << pkt.timestamp << ", event: collapse, prefix_found: " << currpref.str() << ", value: " << currnode.summaryval << endl;
                    }
                }

                if (!collapseacc) {

                    // Insert a new prefix node
                    bool prevchild = pkt.srcPrefix[prevlen];
                    tNodeOnline &prevnode = tree[prevpref] = tNodeOnline();
                    if (flows) filter(cincrement, sincrement, pkt, prevpref, prevlen, prevchild);
                    prevnode.childvals[prevchild] = cincrement;
                    prevnode.summaryval = sincrement;
                    prevnode.timestamp = pkt.timestamp;
                }
            }

        // Expand rule?
        } else if (currnode.childvals[currchild] >= getThreshold(currlen) && currlen != lastlen) {

            // Report pure Heavy-Hitter
            if (pureheavy || reports)
                cout << "timestamp: " << pkt.timestamp << ", event: expand, prefix_found: " << currpref.str() << ", value: " << currnode.summaryval << endl;

            // Subtract HH value from current prefix node
            currnode.childvals[currchild] = 0;
            currnode.summaryval = currnode.childvals[!currchild];

            // Insert a new prefix node
            bool nextchild = pkt.srcPrefix[nextlen];
            tNodeOnline &nextnode = tree.insert(pair<tPrefix,tNodeOnline>(nextpref, tNodeOnline())).first->second;
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

        // Report memory occupancy
        if (reports && timestamp != 0 && timestamp <= pkt.timestamp) {

            // Count valid nodes
            unsigned memocc = 0;
            unsigned histgram[2][32+1] = {0};
            for (auto it = tree.begin(); it != tree.end(); it++) {
                histgram[0][it->first.length]++;
                if (it->second.timestamp + itimeout <= pkt.timestamp) continue;
                histgram[1][it->first.length]++;
                memocc++;
            }

            unsigned memdepth[2] = {0};

            cout << "histogram-incl:";
            for (unsigned i = 0; i <= 32; i++) {
                cout << " " << i << ":" << histgram[0][i];
                if (histgram[0][i] > 0) memdepth[0] = i;
            } cout << endl;

            cout << "histogram-excl:";
            for (unsigned i = 0; i <= 32; i++) {
                cout << " " << i << ":" << histgram[1][i];
                if (histgram[1][i] > 0) memdepth[1] = i;
            } cout << endl;

            cout << "memory-occup: " << tree.size() << "/" << memocc << endl;
            cout << "memory-depth: " << memdepth[0] << "/" << memdepth[1] << endl;

            timestamp += repgran;
        }

        return true;
    }

    virtual void clear() override {
        tree.clear();
    }

    virtual void flush() override {
    }
};

#endif
