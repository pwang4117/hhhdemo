
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
    bool help = false;
};

inline void tArgs::usage() {
    cout << "Usage: " << __progname << " [-h] PCAP_FILES ..." << endl;
    cout << "  -h            Show this help message." << endl;
}

tArgs::tArgs(int argc, char * const argv[]) {

    for (int opt = 0; (opt = getopt(argc, argv, ":h")) != -1; ) switch(opt) {
        case 'h':
            help = true; return;
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

    for (unsigned f = 0; f < args.filecount; f++) {
        cout << "filename: " << args.filenames[f] << endl;

        tPacket pkt;
        uint64_t pcktsCount = 0;
        uint64_t bytesCount = 0;

        tTraceFile tracefile(args.filenames[f]);
        tTraceData tracedata(strfrmt("%s%s", args.filenames[f], ".pdat").c_str(), true);

        while (tracefile.nextPacket(pkt)) {
            if (pkt.ipver != 4) continue; // TODO: IPv6 support

            pcktsCount += 1;
            bytesCount += pkt.length;

            tracedata.savePacket(pkt);
        }

        cout << pcktsCount << " packets, " << bytesCount << " bytes processed." << endl;
    }

} catch(exception &e) {
    cerr << __progname << ": " << e.what() << endl;
    return EXIT_FAILURE;
}
