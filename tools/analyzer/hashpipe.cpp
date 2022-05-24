
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <iostream>
#include <stdexcept>

#include "trace.h"
#include "hashpipe.h"

using namespace std;

extern const char *__progname;

struct tArgs {
    tArgs(int argc, char * const argv[]);
    inline void usage();
    const char *filename;
    uint64_t offset = 0;
    uint64_t time = 0;
    bool help = false;
    unsigned D;
    unsigned S;
};

inline void tArgs::usage() {
    cout << "Usage: " << __progname << " [-h] PDATFILE D S OFFSET TIME" << endl;
    cout << "  -h         Show this help message." << endl;
}

tArgs::tArgs(int argc, char * const argv[]) {
    for (int opt = 0; (opt = getopt(argc, argv, ":hc")) != -1; ) switch(opt) {
        case 'h':
            help = true; return;
        case '?': throw runtime_error(string() + "unknown option '-" + (char) optopt + "'");
        case ':': throw runtime_error(string() + "missing argument for option '-" + (char) optopt + "'");
        default : throw runtime_error(string() + "option '-" + (char) opt + "' not implemented");
    } argv += optind; argc -= optind;
    if (argc != 5) throw runtime_error("missing arguments");
    filename = argv[0];
    D = strtoul(argv[1], nullptr, 10);
    S = strtoul(argv[2], nullptr, 10);
    offset = strtoul(argv[3], nullptr, 10);
    time = strtoul(argv[4], nullptr, 10);
}

int main(int argc, char *argv[]) try {

    tArgs args(argc, argv);
    if (args.help) {
        args.usage(); return EXIT_SUCCESS;
    }

    // cout << "filename: " << args.filename << endl;
    // cout << "D: " << args.D << endl;
    // cout << "S: " << args.S << endl;
    // cout << "offset: " << args.offset << endl;
    // cout << "time: " << args.time << endl;

    tPacket pkt;
    uint64_t pcktsCount = 0;
    uint64_t bytesCount = 0;
    uint64_t tbegin = 0;
    uint64_t tend = ~0UL;

    tHashPipe hashpipe(args.D, args.S);

    tTraceData tracefile(args.filename);
    while (tracefile.nextPacket(pkt)) {

        // Set time offset for the beginning of the time interval
        if (tbegin == 0) {
            tbegin = pkt.timestamp + args.offset;
            if (args.time != 0) tend = tbegin + args.time;
        }

        // TODO: IPv6 support
        if (pkt.ipver != 4) continue;

        // Before time interval to extract
        if (pkt.timestamp < tbegin || pkt.timestamp >= tend) continue;

        // Call HashPipe engine
        hashpipe.processPacket(pkt);

        pcktsCount += 1;
        bytesCount += pkt.length;
    }

    tPrefix pref; pref.length = 32;
    multimap<unsigned,unsigned> topflows = hashpipe.getFlows();
    for (auto const& value: topflows) {
        pref.prefix = value.second;
        cout << pref.str(false) << "," << value.first << endl;
    }

    cout << "Processed " << pcktsCount << " packets, " << bytesCount << " bytes." << endl;

} catch(exception &e) {
    cerr << __progname << ": " << e.what() << endl;
    return 2;
}
