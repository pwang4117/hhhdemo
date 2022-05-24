
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <iostream>
#include <stdexcept>

#include "trace.h"

using namespace std;

extern const char *__progname;

struct tArgs {
    tArgs(int argc, char * const argv[]);
    inline void usage();
    char * const *filenames;
    unsigned filecount = 0;
    uint64_t offset = 0;
    uint64_t time = 0;
    bool help = false;
    bool csv = false;
};

inline void tArgs::usage() {
    cout << "Usage: " << __progname << " [-h] INFILE OUTFILE ..." << endl;
    cout << "  -h         Show this help message." << endl;
    cout << "  -c         Output in CSV." << endl;
    cout << "  -o OFFSET  Time offset to shift beginning of the interval (in us)." << endl;
    cout << "  -t TIME    Time interval to extract (in us)." << endl;
}

tArgs::tArgs(int argc, char * const argv[]) {

    for (int opt = 0; (opt = getopt(argc, argv, ":hco:t:")) != -1; ) switch(opt) {
        case 'h':
            help = true; return;
        case 'c':
            csv = true; break;
        case 'o':
            offset = strtoul(optarg, nullptr, 10); break;
        case 't':
            time = strtoul(optarg, nullptr, 10); break;
        case '?': throw runtime_error(string() + "unknown option '-" + (char) optopt + "'");
        case ':': throw runtime_error(string() + "missing argument for option '-" + (char) optopt + "'");
        default : throw runtime_error(string() + "option '-" + (char) opt + "' not implemented");
    } argv += optind; argc -= optind;
    if (argc == 0) throw runtime_error("missing input file");
    filenames = argv; filecount = argc;
}

int main(int argc, char *argv[]) try {

    tArgs args(argc, argv);
    if (args.help) {
        args.usage(); return EXIT_SUCCESS;
    }

    cout << "filename: " << args.filenames[0] << endl;

    tPacket pkt;
    uint64_t pcktsCount = 0;
    uint64_t bytesCount = 0;
    uint64_t tbegin = 0;
    uint64_t tend = ~0UL;

    tTraceData tracefile(args.filenames[0]);
    tTraceData tracedata(args.filenames[1], true, args.csv);

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

        pcktsCount += 1;
        bytesCount += pkt.length;

        tracedata.savePacket(pkt);
    }

    cout << pcktsCount << " packets, " << bytesCount << " bytes processed." << endl;

} catch(exception &e) {
    cerr << __progname << ": " << e.what() << endl;
    return EXIT_FAILURE;
}
