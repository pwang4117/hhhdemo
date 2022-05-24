
#include <map>
#include <string>
#include <sstream>
#include <cstdlib>
#include <fstream>
#include <unistd.h>
#include <iostream>
#include <stdexcept>

#include "../analyzer/model.h"

using namespace std;

extern const char *__progname;

struct tArgs {
    tArgs(int argc, char * const argv[]);
    inline void usage();
    char * const *filenames;
    unsigned filecount = 0;
    uint64_t atimeout = 0;
    bool pureheavy = false;
    uint64_t threshold = 10000;
    uint64_t speed = 0;
    double quotient = 0.0;
    unsigned firstlen = 1;
    unsigned lastlen = 32;
    unsigned colstrategy = 2;
    bool help = false;
    bool offline = false;
    bool origdata = false;
    bool reports = false;
    bool sum = false;
    bool newinvalidation = true;
    bool collapseacc = false;
};

inline void tArgs::usage() {
    cout << "Usage: " << __progname << " [-hSHr] [-x RPLEN] [-a ATIMEOUT] [-s SPEED] [-t THRESHOLD] COUNTER_FILES ..." << endl;
    cout << "  -h            Show this help message." << endl;
    cout << "  -H            Print pure heavy-hitters too." << endl;
    cout << "  -r            Report all changes in the prefix tree structure." << endl;
    cout << "  -S            Sum all the counters reported for the same prefix." << endl;
    cout << "  -x RPLEN      Root prefix length (eg. 1 or 16, 1 is default)." << endl;
    cout << "  -a ATIMEOUT   Active timeout in usec (for periodic reports)." << endl;
    cout << "  -s SPEED      Set threshold according the speed (in bytes per second)." << endl;
    cout << "  -t THRESHOLD  Manual threshold settings for heavy hitter detection (in bytes)." << endl;
}

tArgs::tArgs(int argc, char * const argv[]) {

    for (int opt = 0; (opt = getopt(argc, argv, ":hHSrx:a:t:s:")) != -1; ) switch(opt) {
        case 'h':
            help = true; return;
        case 'H':
            pureheavy = true; break;
        case 'S':
            sum = true; break;
        case 'c':
            colstrategy = strtoul(optarg, nullptr, 10); break;
        case 'v':
            newinvalidation = false; break;
        case 'A':
            collapseacc = true; break;
        case 'r':
            reports = true; break;
        case 'x':
            firstlen = strtoul(optarg, nullptr, 10);
            if (firstlen < 1 || firstlen >= 32) firstlen = 1;
            break;
        case 'a':
            atimeout = strtoul(optarg, nullptr, 10); break;
        case 't':
            threshold = strtoul(optarg, nullptr, 10); break;
        case 's':
            speed = strtoul(optarg, nullptr, 10); break;

        case '?': throw runtime_error(string() + "unknown option '-" + (char) optopt + "'");
        case ':': throw runtime_error(string() + "missing argument for option '-" + (char) optopt + "'");
        default : throw runtime_error(string() + "option '-" + (char) opt + "' not implemented");
    } argv += optind; argc -= optind;
    if (argc == 0) throw runtime_error("missing input file");
    filenames = argv; filecount = argc;
}

struct tNodeOffline {
    bool hh = false;
    bool hhh = false;
    uint64_t hhvalue = 0;
    uint64_t hhhvalue = 0;
};

int main(int argc, char *argv[]) try {

    tArgs args(argc, argv);
    if (args.help) {
        args.usage(); return EXIT_SUCCESS;
    }

    if (args.speed > 0)
        args.threshold = args.speed * args.atimeout / 1000000;

    map<tPrefix,tNodeOffline> tree;

    for (unsigned f = 0; f < args.filecount; f++) {
        cout << "filename: " << args.filenames[f] << endl;

        ifstream infile(args.filenames[f]);
        for (string line; getline(infile, line);) {
            if (line.substr(0,5) == "level") continue;

            char symbl;
            tPrefix prefix;
            uint64_t packets;
            unsigned ip1, ip2, ip3, ip4;

            istringstream iss(line);
            if (!(iss >> ip1 >> symbl >> ip2 >> symbl >>
            ip3 >> symbl >> ip4 >> symbl >> packets))
                continue; // error
            unsigned char bytes[4] = {
                (unsigned char) ip1, (unsigned char) ip2,
                (unsigned char) ip3, (unsigned char) ip4 };

            prefix.set(bytes);
            auto it = tree.find(prefix);
            if (it == tree.end()) {
                it = tree.insert(pair<tPrefix,tNodeOffline>(prefix, tNodeOffline())).first;
                it->second.hhvalue = packets;
                it->second.hhhvalue = packets;
            } else if (args.sum) {
                it->second.hhvalue += packets;
                it->second.hhhvalue += packets;
            }
        }

        // Build hierarchy
        for (auto it = tree.rbegin(); it != tree.rend(); it++) {
            it->second.hh = it->second.hhvalue >= args.threshold;
            it->second.hhh = it->second.hhhvalue >= args.threshold;

            if (it->first.length > args.firstlen) {
                tNodeOffline node; tPrefix prefix = it->first;
                prefix.length -= 1; prefix.norm();

                auto par = tree.find(prefix);
                if (par == tree.end()) {
                    par = tree.insert(pair<tPrefix,tNodeOffline>(prefix, node)).first;
                }

                par->second.hhvalue += it->second.hhvalue;
                if (!it->second.hhh) par->second.hhhvalue += it->second.hhhvalue;
            }
        }

        // Hierarchy heavy-hitters list
        for (auto it = tree.begin(); it != tree.end(); it++) {
            if (!it->second.hhh) continue;
            cout << "timestamp: " << f << ", hhh: 1, prefix: " << it->first.str() << ", value: " << it->second.hhhvalue << endl;
        }

        // Heavy-hitters list
        if (args.pureheavy) {
            for (auto it = tree.begin(); it != tree.end(); it++) {
                if (!it->second.hh) continue;
                cout << "timestamp: " << f << ", hhh: 0, prefix: " << it->first.str() << ", value: " << it->second.hhvalue << endl;
            }
        }

        // Report counters
        if (args.reports) {
            for (auto it = tree.begin(); it != tree.end(); it++) {
                if (it->first.length != 32) continue;
                cout << "timestamp," << f << ",report,prefix," << it->first.str() << ",value," << it->second.hhvalue << endl;
            }
        }

        tree.clear();
    }

} catch(exception &e) {
    cerr << __progname << ": " << e.what() << endl;
    return 2;
}
