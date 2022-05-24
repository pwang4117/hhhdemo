
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <iostream>
#include <stdexcept>

#include "trace.h"
#include "model-offline.h"
#include "model-online.h"
#include "model-hash.h"

using namespace std;

extern const char *__progname;

struct tArgs {
    tArgs(int argc, char * const argv[]);
    inline void usage();
    char * const *filenames;
    unsigned filecount = 0;
    uint64_t offset = 0;
    uint64_t atimeout = 0;
    uint64_t itimeout = 0;
    uint64_t repgran = 0;
    uint64_t injecttime = 0;
    unsigned injectnum = 1;
    unsigned injectden = 1;
    const char *injectfile = nullptr;
    uint64_t threshold = 10000;
    uint64_t speed = 0;
    uint64_t divider = 0;
    uint64_t memory = 0;
    double quotient = 0.0;
    unsigned firstlen = 1;
    unsigned colstrategy = 2;
    bool help = false;
    bool offline = false;
    bool firstshot = false;
    bool pureheavy = false;
    bool origdata = false;
    bool reports = false;
    bool newinvalidation = true;
    bool collapseacc = false;
    double filter_false_positive_probability = 0.1;
    unsigned long long filter_maximum_size = 10000000;
    unsigned long long filter_projected_element_count = 100000;

    bool packets = false;
    bool flows = false;
};

inline void tArgs::usage() {
    cout << "Usage: " << __progname << " [-hoAHRfSrvpF] [-c COLSTR] [-b BFSIZE] [-B BFPROB] [-e BFELEMS] [-x RPLEN] [-m MEMORY] [-a ATIMEOUT] [-i ITIMEOUT] [-O OFFSET] [-q QUOTIENT] [-d DIVIDER] [-s SPEED] [-t THRESHOLD] [-I INJECTFILE] [-T INJECTTIME] [-S INJECTSAMP] PDAT_FILES ..." << endl;
    cout << "  -h            Show this help message." << endl;
    cout << "  -H            Print pure heavy-hitters too." << endl;
    cout << "  -A            Accelerate collapsing of the prefix tree." << endl;
    cout << "  -f            Run offline analysis (online analysis is default)." << endl;
    cout << "  -S            Stop after first window report (only for offline analysis)." << endl;
    cout << "  -p            Use number of packets instead of number of bytes." << endl;
    cout << "  -F            Use number of flows instead of number of packets or bytes." << endl;
    cout << "  -o            Use original PCAP as input instead extracted data only." << endl;
    cout << "  -v            Turn off the new memory access efficient approach to invalidation." << endl;
    cout << "  -r            Report all changes in the prefix tree structure." << endl;
    cout << "  -c COLSTR     Collisions strategy (0-ignore, 1-skip, 2-adapt-bit, 3-adapt-full, only for -m option)." << endl;
    cout << "  -R REPGRAN    Reports granularity in usec." << endl;
    cout << "  -b BFSIZE     Bloom filter maximum size (in bits for a single stage)." << endl;
    cout << "  -B BFPROB     Bloom filter false positive probability." << endl;
    cout << "  -e BFELEMS    Bloom filter projected elements." << endl;
    cout << "  -x RPLEN      Root prefix length (eg. 1 or 16, 1 is default)." << endl;
    cout << "  -m MEMORY     Use hash based table for evaluation and set available memory." << endl;
    cout << "  -d DIVIDER    Use adaptive time window according the divider." << endl;
    cout << "  -a ATIMEOUT   Active timeout in usec (for periodic reports)." << endl;
    cout << "  -i ITIMEOUT   Inactive timeout in usec (for structure invalidation, online only)." << endl;
    cout << "  -O OFFSET     Offset time of the windows in usec (from the beginning of the trace)." << endl;
    cout << "  -q QUOTIENT   Set threshold according the quotient (fraction, offline only)." << endl;
    cout << "  -s SPEED      Set threshold according the speed (in bytes per second)." << endl;
    cout << "  -t THRESHOLD  Manual threshold settings for heavy hitter detection (in bytes)." << endl;
    cout << "  -I INJECTFILE PDAT file with traffic for injection." << endl;
    cout << "  -T INJECTTIME Time from the start of traffic in usecs where to inject specified file." << endl;
    cout << "  -N INJECTNUM  Sampling numerator of injected file." << endl;
    cout << "  -D INJECTDEN  Sampling denominator of injected file." << endl;
}

tArgs::tArgs(int argc, char * const argv[]) {

    for (int opt = 0; (opt = getopt(argc, argv, ":hHFN:D:R:Arc:ovb:e:O:B:I:T:x:m:d:fSpa:i:t:q:s:")) != -1; ) switch(opt) {
        case 'h':
            help = true; return;
        case 'H':
            pureheavy = true; break;
        case 'c':
            colstrategy = strtoul(optarg, nullptr, 10); break;
        case 'v':
            newinvalidation = false; break;
        case 'A':
            collapseacc = true; break;
        case 'd':
            divider = strtoul(optarg, nullptr, 10); break;
        case 'b':
            filter_maximum_size = strtoull(optarg, nullptr, 10); break;
        case 'B':
            filter_false_positive_probability = strtod(optarg, nullptr); break;
        case 'e':
            filter_projected_element_count = strtod(optarg, nullptr); break;
        case 'o':
            origdata = true; break;
        case 'S':
            firstshot = true; break;
        case 'f':
            offline = true; break;
        case 'r':
            reports = true; break;
        case 'm':
            memory = strtoul(optarg, nullptr, 10); break;
        case 'x':
            firstlen = strtoul(optarg, nullptr, 10);
            if (firstlen < 1 || firstlen >= 32) firstlen = 1;
            break;
        case 'N':
            injectnum = strtoul(optarg, nullptr, 10); break;
        case 'D':
            injectden = strtoul(optarg, nullptr, 10); break;
        case 'R':
            repgran = strtoul(optarg, nullptr, 10); break;
        case 'O':
            offset = strtoul(optarg, nullptr, 10); break;
        case 'a':
            atimeout = strtoul(optarg, nullptr, 10); break;
        case 'i':
            itimeout = strtoul(optarg, nullptr, 10); break;
        case 't':
            threshold = strtoul(optarg, nullptr, 10); break;
        case 's':
            speed = strtoul(optarg, nullptr, 10); break;
        case 'q':
            quotient = strtod(optarg, nullptr); break;
        case 'I':
            injectfile = optarg; break;
        case 'T':
            injecttime = strtoul(optarg, nullptr, 10); break;
        case 'p':
            packets = true; break;
        case 'F':
            flows = true; break;

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

    tModel *model;
    if (args.offline) {
        tModelOffline *offmodel = new tModelOffline();
        offmodel->pureheavy = args.pureheavy;
        offmodel->threshold = (args.speed > 0) ? args.speed * args.atimeout / 1000000 : args.threshold;
        offmodel->quotient = args.quotient;
        offmodel->timeout = args.atimeout;
        offmodel->firstshot = args.firstshot;
        offmodel->bytes = !args.packets;
        offmodel->flows = args.flows;
        offmodel->reports = args.reports;
        offmodel->collapseacc = args.collapseacc;
        offmodel->firstlen = args.firstlen;
        offmodel->lastlen = 32;
        model = offmodel;
    } else if (args.memory > 0) {
        tModelHash *hashmodel = new tModelHash();
        hashmodel->pureheavy = args.pureheavy;
        hashmodel->threshold = args.threshold;
        hashmodel->speed = args.speed;
        hashmodel->memory = args.memory;
        hashmodel->atimeout = (args.atimeout > 0) ? args.atimeout : 10000000;
        hashmodel->itimeout = (args.itimeout > 0) ? args.itimeout : 60000000;
        hashmodel->bytes = !args.packets;
        hashmodel->flows = args.flows;
        hashmodel->reports = args.reports;
        hashmodel->firstlen = args.firstlen;
        hashmodel->lastlen = 32;
        hashmodel->hashskip = args.colstrategy == 1;
        hashmodel->hashcopt = args.colstrategy == 2;
        hashmodel->hashadapt = args.colstrategy == 3;
        hashmodel->newinvalidation = args.newinvalidation;
        hashmodel->collapseacc = args.collapseacc;
        hashmodel->filter_maximum_size = args.filter_maximum_size;
        hashmodel->filter_false_positive_probability = args.filter_false_positive_probability;
        hashmodel->filter_projected_element_count = args.filter_projected_element_count;
        hashmodel->init(args.divider);
        model = hashmodel;
    } else {
        tModelOnline *onmodel = new tModelOnline();
        onmodel->pureheavy = args.pureheavy;
        onmodel->threshold = args.threshold;
        onmodel->speed = args.speed;
        onmodel->atimeout = (args.atimeout > 0) ? args.atimeout : 10000000;
        onmodel->itimeout = (args.itimeout > 0) ? args.itimeout : 60000000;
        onmodel->repgran = (args.repgran > 0) ? args.repgran : onmodel->atimeout;
        onmodel->bytes = !args.packets;
        onmodel->flows = args.flows;
        onmodel->reports = args.reports;
        onmodel->firstlen = args.firstlen;
        onmodel->lastlen = 32;
        onmodel->newinvalidation = args.newinvalidation;
        onmodel->collapseacc = args.collapseacc;
        onmodel->init(args.divider);
        model = onmodel;
    }

    tPacket pkt;
    uint64_t pcktsCount = 0;
    uint64_t bytesCount = 0;
    uint64_t start = 0;
    uint64_t ostart = 0;

    tPacket injpkt;
    uint64_t injPcktsCount = 0;
    uint64_t injBytesCount = 0;
    uint64_t injStart = 0;
    uint32_t injSampl = args.injectden;

    tTrace *injTrace = nullptr;
    if (args.injectfile != nullptr) {
        if (!args.origdata) {
            injTrace = new tTraceData(args.injectfile);
        } else {
#ifndef NOPCAP
            injTrace = new tTraceFile(args.injectfile);
#else
            assert(false && "Compiled without PCAP support");
#endif
        }

        while (true) {
            if (injTrace->nextPacket(injpkt)) {
                cout << "TRUE: " << injSampl << endl;

                if (injpkt.ipver != 4) continue; // TODO: IPv6 support
                injStart = injpkt.timestamp;
                cout << "injstart: " << injStart << endl;

                break;
            } else {
                cout << "FALSE" << endl;

                delete injTrace;
                injTrace = nullptr;
                break;
            }
        }
    }

    for (unsigned f = 0; f < args.filecount; f++) {

        tTrace *trace = nullptr;
        cout << "filename: " << args.filenames[f] << endl;
        if (!args.origdata) {
            trace = new tTraceData(args.filenames[f]);
        } else {
#ifndef NOPCAP
            trace = new tTraceFile(args.filenames[f]);
#else
            assert(false && "Compiled without PCAP support");
#endif
        }

        while (trace->nextPacket(pkt)) {
            if (pkt.ipver != 4) continue; // TODO: IPv6 support

            if (start == 0) {
                start = pkt.timestamp;
                ostart = pkt.timestamp + args.offset;
                cout << "tracestart: " << start << endl;
                cout << "offsetstart: " << ostart << endl;
            }

            // Skip offset time from the beginning of the trace
            if (ostart > pkt.timestamp) continue;

//            cout << injpkt.srcPrefix.str() << endl;
//            cout << injpkt.dstPrefix.str() << endl;
//            cout << injpkt.length << endl;
//            cout << injpkt.ipver << endl;
//            cout << injpkt.timestamp << "(" << injpkt.timestamp-injStart+args.injecttime << ")" << endl;
//            cout << endl;
//
//            cout << pkt.srcPrefix.str() << endl;
//            cout << pkt.dstPrefix.str() << endl;
//            cout << pkt.length << endl;
//            cout << pkt.ipver << endl;
//            cout << pkt.timestamp << "(" << pkt.timestamp-start << ")" << endl;
//            cout << endl;
//
//            cout << "---" << endl;


            if (injTrace != nullptr) {
                while (pkt.timestamp-start >= injpkt.timestamp-injStart+args.injecttime) {

                    pcktsCount += 1;
                    bytesCount += injpkt.length;

                    injPcktsCount += 1;
                    injBytesCount += injpkt.length;

                    injpkt.timestamp = injpkt.timestamp-injStart+args.injecttime+start;

                    model->processPacket(injpkt);

                    while (true) {
                        if (injSampl == 0)
                            injSampl = args.injectden;

                        if (injTrace->nextPacket(injpkt)) {
                            if (injpkt.ipver != 4) continue; // TODO: IPv6 support
                            if (--injSampl >= args.injectnum) continue;
                            break;
                        } else {
                            delete injTrace;
                            injTrace = nullptr;
                            break;
                        }
                    }

                }
            }

            pcktsCount += 1;
            bytesCount += pkt.length;

            if (!model->processPacket(pkt)) break;
        }

        delete trace;
        trace = nullptr;
    }

    model->flush();

    delete model;
    model = nullptr;

    cout << endl << pcktsCount << " packets, " << bytesCount << " bytes processed." << endl;

} catch(exception &e) {
    cerr << __progname << ": " << e.what() << endl;
    return 2;
}
