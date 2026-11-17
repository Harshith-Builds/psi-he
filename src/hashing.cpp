// Parameter sets, item encoding (permutation-based hashing), cuckoo hashing (client),
// simple hashing + polynomial interpolation (server).
#include <sodium.h>

#include <chrono>
#include <stdexcept>

#include "psi.h"

namespace psi {

Params ParamsByName(const std::string& n) {
    Params P;
    P.name = n;
    if (n == "A") {  // Part 2 design: 2 partitions x 160 roots, 8 query powers
        P.partitions = 2; P.degree = 160; P.serverMax = 1u << 20; P.multDepth = 5; P.keepTowers = 3;
    } else if (n == "B") {  // Part 2 "budget lever": 4 partitions x 80 roots, 7 query powers
        P.partitions = 4; P.degree = 80; P.serverMax = 1u << 20; P.multDepth = 5; P.keepTowers = 3;
    } else if (n == "C") {  // smaller service: 2^16 users, 1 partition x 52 roots, 6 query powers
        P.partitions = 1; P.degree = 52; P.serverMax = 1u << 16; P.multDepth = 5; P.keepTowers = 3;
    } else if (n == "T") {  // fast set for unit tests: 2^14 users, 1 x 20 roots
        P.partitions = 1; P.degree = 20; P.serverMax = 1u << 14; P.multDepth = 4; P.keepTowers = 3;
    } else {
        throw std::runtime_error("unknown parameter set " + n);
    }
    return P;
}
std::vector<std::string> ParamSetNames() { return {"A", "B", "C"}; }

u64 MulMod(u64 a, u64 b, u64 m) { return (u64)((u128)a * b % m); }

static inline u64 SplitMix(u64 x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}
static const u64 kSeeds[4] = {0, 0x243F6A8885A308D3ULL, 0x13198A2E03707344ULL, 0xA4093822299F31D0ULL};

u64 BinOf(u128 y, uint32_t i, const Params& P) {
    u64 mask = P.bins() - 1;
    u64 yR = (u64)y & mask;
    u64 yL = (u64)(y >> P.logBins);
    return yR ^ (SplitMix(yL ^ kSeeds[i]) & mask);
}
u64 ValueOf(u128 y, uint32_t i, const Params& P) { return 4 * (u64)(y >> P.logBins) + i; }

bool CuckooInsert(const std::vector<u128>& ys, const Params& P, CuckooTable& T, std::mt19937_64& rng) {
    T.value.assign(P.bins(), 0);
    T.owner.assign(P.bins(), -1);
    std::vector<uint32_t> which(ys.size(), 0);  // hash index currently used by each item
    for (size_t idx = 0; idx < ys.size(); ++idx) {
        int cur = (int)idx;
        uint32_t i = 1 + rng() % 3;
        for (int kick = 0; kick < 1000; ++kick) {
            // try a free bin among the three first
            bool placed = false;
            for (uint32_t h = 1; h <= 3 && !placed; ++h) {
                u64 b = BinOf(ys[cur], h, P);
                if (T.owner[b] == -1) {
                    T.owner[b] = cur; T.value[b] = ValueOf(ys[cur], h, P); which[cur] = h; placed = true;
                }
            }
            if (placed) { cur = -1; break; }
            // evict the occupant of a random candidate bin
            u64 b = BinOf(ys[cur], i, P);
            int ev = T.owner[b];
            T.owner[b] = cur; T.value[b] = ValueOf(ys[cur], i, P); which[cur] = i;
            cur = ev;
            do { i = 1 + rng() % 3; } while (i == which[cur]);
        }
        if (cur != -1) return false;
    }
    return true;
}

ServerDB BuildServerDB(const std::vector<u128>& ys, const Params& P) {
    if (ys.size() > P.serverMax) throw std::runtime_error("server set larger than provisioned");
    const u64 t = P.t;
    const uint32_t nb = P.bins(), D = P.degree;
    std::vector<std::vector<u64>> bins(nb);
    for (auto& b : bins) b.reserve(3 * P.serverMax / nb + 64);
    for (u128 y : ys)
        for (uint32_t i = 1; i <= 3; ++i) bins[BinOf(y, i, P)].push_back(ValueOf(y, i, P));
    ServerDB db;
    db.P = P;
    size_t total = 0;
    for (auto& b : bins) { db.maxLoad = std::max(db.maxLoad, b.size()); total += b.size(); }
    db.meanLoad = double(total) / nb;
    if (db.maxLoad > P.capacity())
        throw std::runtime_error("bin overflow: load " + std::to_string(db.maxLoad) + " > capacity " +
                                 std::to_string(P.capacity()));
    db.coef.assign(size_t(P.partitions) * (D + 1), std::vector<u64>(nb));
    const u64 dummyLo = u64(1) << (P.yLBits() + 2);  // real values are < 2^(yL+2); dummies in [2^(yL+2), t)
#pragma omp parallel
    {
        std::mt19937_64 rng(randombytes_random() ^ (u64(randombytes_random()) << 32));
        std::uniform_int_distribution<u64> dummy(dummyLo, t - 1);
        std::vector<u64> c(D + 1), roots(D);
#pragma omp for schedule(static)
        for (int64_t b = 0; b < (int64_t)nb; ++b) {
            for (uint32_t p = 0; p < P.partitions; ++p) {
                for (uint32_t r = 0; r < D; ++r) {
                    size_t k = size_t(p) * D + r;
                    roots[r] = k < bins[b].size() ? bins[b][k] : dummy(rng);
                }
                std::fill(c.begin(), c.end(), 0);
                c[0] = 1;
                for (uint32_t d = 0; d < D; ++d) {  // multiply by (x - root)
                    u64 nv = t - roots[d];
                    c[d + 1] = 0;
                    for (uint32_t j = d + 1; j >= 1; --j) c[j] = (c[j - 1] + MulMod(nv, c[j], t)) % t;
                    c[0] = MulMod(nv, c[0], t);
                }
                for (uint32_t j = 0; j <= D; ++j) db.coef[size_t(p) * (D + 1) + j][b] = c[j];
            }
        }
    }
    return db;
}

u64 PolyEval(const ServerDB& db, uint32_t p, uint32_t bin, u64 x) {
    const auto& P = db.P;
    u64 acc = 0;
    for (int j = P.degree; j >= 0; --j) acc = (MulMod(acc, x, P.t) + db.coef[size_t(p) * (P.degree + 1) + j][bin]) % P.t;
    return acc;
}

std::string RandomPhone(std::mt19937_64& rng) {
    // NANP: NPA 2-9xx, NXX 2-9xx, line 0000-9999
    auto d = [&](int lo, int hi) { return char('0' + lo + rng() % (hi - lo + 1)); };
    std::string s = "+1";
    s += d(2, 9); s += d(0, 9); s += d(0, 9);
    s += d(2, 9); s += d(0, 9); s += d(0, 9);
    for (int i = 0; i < 4; ++i) s += d(0, 9);
    return s;
}

double Now() {
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
}  // namespace psi
