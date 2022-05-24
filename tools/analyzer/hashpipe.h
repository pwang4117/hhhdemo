#ifndef HASHPIPE_H_
#define HASHPIPE_H_

#include <vector>

#include "model.h"

using namespace std;

class tHashPipe {
    public:
        void processPacket(tPacket &pkt);
        multimap<unsigned,unsigned> getFlows();

        tHashPipe(unsigned D, unsigned S) {
            _D = D;
            _S = S;
            _buckets.resize(S, pair<unsigned,unsigned>(0,0));
        };

        vector<pair<unsigned,unsigned>> &getBuckets() {
            return _buckets;
        };

        void reset() {
            fill(_buckets.begin(), _buckets.end(), pair<unsigned,unsigned>(0,0));
        }

    private:
        // Number of hash stages/tables
        unsigned _D;
        // Size of a hash stage/table
        unsigned _S;
        // Array of hash stages/tables
        vector<pair<unsigned,unsigned>> _buckets;

    // Hardcoded hash function constants
    const unsigned P = 9029;
    const unsigned hashA[256] = {10273, 8941, 11597, 9203, 12289, 11779, 421, 199, 79, 83, 89, 97, 101, 103, 107, 109,
        113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
        233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
        359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479,
        487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 1153, 1163,
        1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289,
        1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429,
        1433, 1439, 1447, 1451};
    const unsigned hashB[256] = {12037, 12289, 9677, 11447, 8837, 10847, 73, 3079, 613, 617, 619, 631, 641, 643, 647,
        653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
        809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
        947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063,
        1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193,
        1201, 1213, 1217, 1223, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543,
        1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657,
        3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331};
};

void tHashPipe::processPacket(tPacket &pkt) {

    unsigned keyBeingCarried = pkt.srcPrefix.prefix;
    unsigned valueBeingCarried = 1;

    for (unsigned k = 0; k < _D; k++) {
        unsigned index = (unsigned) ((hashA[k] * (unsigned long) keyBeingCarried + hashB[k]) % P) % (_S / _D) + (k * _S / _D);

        // New flow, position empty, insert record
        if (_buckets[index].first == 0) {
            _buckets[index].first = keyBeingCarried;
            _buckets[index].second = valueBeingCarried;
            break;

            // Existing record, just update the counter
        } else if (_buckets[index].first == keyBeingCarried) {
            _buckets[index].second += valueBeingCarried;
            break;
        }

        // Non-empty first stage, or smaller counter
        if (k == 0 || _buckets[index].second < valueBeingCarried) {
            // Kick out the item
            unsigned keyKicked = _buckets[index].first;
            unsigned valueKicked = _buckets[index].second;

            // Replace the kicked item with the carried item
            _buckets[index].first = keyBeingCarried;
            _buckets[index].second = valueBeingCarried;

            // Carry the kicked item over
            keyBeingCarried = keyKicked;
            valueBeingCarried = valueKicked;
        }
    }
}

multimap<unsigned,unsigned> tHashPipe::getFlows() {
    map<unsigned,unsigned> flows;

    for (auto const& value: _buckets) {
        if (value.first == 0) continue;

        auto par = flows.find(value.first);
        if (par == flows.end()) {
            par = flows.insert(pair<unsigned,unsigned>(value.first, 0)).first;
        }

        par->second += value.second;
    }

    return flip_map(flows);
}

#endif
