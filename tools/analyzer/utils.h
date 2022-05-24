#ifndef UTILSTYPES_H_
#define UTILSTYPES_H_

#include <map>
#include <string>
#include <memory>
#include <algorithm>

using namespace std;

// Credits: http://stackoverflow.com/questions/2342162/stdstring-formatting-like-sprintf
template<typename ... Args>
string strfrmt(const string& format, Args ... args) {
    size_t size = 1 + snprintf(nullptr, 0, format.c_str(), args ...);
    unique_ptr<char[]> buf(new char[size]);
    snprintf(buf.get(), size, format.c_str(), args ...);
    return string(buf.get(), buf.get() + size - 1);
}

// Flips a pair A,B to B,A pair
// Credits: https://stackoverflow.com/questions/5056645/sorting-stdmap-using-value
template<typename A, typename B>
pair<B,A> flip_pair(const std::pair<A,B> &p) {
    return pair<B,A>(p.second, p.first);
}

// Flips an associative container of A,B pairs to B,A pairs
// Credits: https://stackoverflow.com/questions/5056645/sorting-stdmap-using-value
template<typename A, typename B, template<class,class,class...> class M, class... Args>
multimap<B,A> flip_map(const M<A,B,Args...> &src) {
    multimap<B,A> dst;
    transform(src.begin(), src.end(), inserter(dst, dst.begin()), flip_pair<A,B>);
    return dst;
}

#endif
