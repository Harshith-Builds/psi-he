// Correctness tests. Exit code 0 iff every check passes.   psi_tests [--quick]
#include <sodium.h>

#include <cstring>
#include <iostream>
#include <unordered_set>

#include "protocol.h"

using namespace psi;

static int g_fail = 0, g_checks = 0;
#define CHECK(cond)                                                                    \
    do {                                                                               \
        ++g_checks;                                                                    \
        if (!(cond)) { ++g_fail; std::cerr << "    FAILED: " #cond " (line " << __LINE__ << ")\n"; } \
    } while (0)

static std::mt19937_64 rng(12345);
static u128 RandY(uint32_t sigma) {
    u128 y = ((u128)rng() << 64) | rng();
    return y & ((((u128)1) << sigma) - 1);
}
static void Run(const char* name, void (*f)()) {
    int before = g_fail;
    double t0 = Now();
    f();
    std::cout << (g_fail == before ? "[PASS] " : "[FAIL] ") << name << "  (" << Now() - t0 << " s)\n";
}

// ---------------------------------------------------------------- encoding & hashing
static void TestEncodingInvertible() {
    Params P = ParamsByName("A");
    for (int n = 0; n < 100000; ++n) {
        u128 y = RandY(P.sigma);
        for (uint32_t i = 1; i <= 3; ++i) {
            u64 b = BinOf(y, i, P), x = ValueOf(y, i, P);
            CHECK(x % 4 == i);                               // never 0 mod 4: empty-bin filler 0 never matches
            CHECK(x < (u64(1) << (P.yLBits() + 2)));         // below the dummy-root range
            CHECK(x < P.t);
            // (bin, value) determines y: no two distinct OPRF outputs can match in a slot
            u64 yL = x >> 2;
            u64 yR = b ^ (BinOf((u128)yL << P.logBins, i, P));  // BinOf with yR = 0 gives h_i(yL)
            CHECK((((u128)yL << P.logBins) | yR) == y);
        }
    }
}

static void TestCuckoo() {
    Params P = ParamsByName("A");
    for (int rep = 0; rep < 50; ++rep) {
        std::vector<u128> ys(P.clientMax);
        for (auto& y : ys) y = RandY(P.sigma);
        CuckooTable T;
        CHECK(CuckooInsert(ys, P, T, rng));
        std::vector<int> seen(ys.size(), 0);
        for (u64 b = 0; b < P.bins(); ++b) {
            if (T.owner[b] < 0) { CHECK(T.value[b] == 0); continue; }
            seen[T.owner[b]]++;
            u128 y = ys[T.owner[b]];
            bool ok = false;
            for (uint32_t i = 1; i <= 3; ++i) ok |= (BinOf(y, i, P) == b && ValueOf(y, i, P) == T.value[b]);
            CHECK(ok);
        }
        for (int s : seen) CHECK(s == 1);
    }
}

static void TestInterpolation() {
    Params P = ParamsByName("C");
    std::vector<u128> ys(20000);
    for (auto& y : ys) y = RandY(P.sigma);
    ServerDB db = BuildServerDB(ys, P);
    for (size_t n = 0; n < 2000; ++n) {  // members: zero in exactly the right bin
        u128 y = ys[n];
        for (uint32_t i = 1; i <= 3; ++i) {
            u64 b = BinOf(y, i, P), x = ValueOf(y, i, P);
            bool zero = false;
            for (uint32_t p = 0; p < P.partitions; ++p) zero |= PolyEval(db, p, b, x) == 0;
            CHECK(zero);
        }
    }
    for (int n = 0; n < 2000; ++n) {  // non-members and the empty-bin filler 0 never evaluate to zero
        u128 y = RandY(P.sigma);
        uint32_t i = 1 + n % 3;
        for (uint32_t p = 0; p < P.partitions; ++p) {
            CHECK(PolyEval(db, p, BinOf(y, i, P), ValueOf(y, i, P)) != 0);
            CHECK(PolyEval(db, p, n % P.bins(), 0) != 0);
        }
    }
    CHECK(db.maxLoad <= P.capacity());
}

static void TestOverflowRejected() {
    Params P = ParamsByName("T");
    P.serverMax = 1u << 20;  // far more items than the T layout can hold
    std::vector<u128> ys(1u << 17);
    for (auto& y : ys) y = RandY(P.sigma);
    bool threw = false;
    try { BuildServerDB(ys, P); } catch (const std::exception&) { threw = true; }
    CHECK(threw);
}

// ---------------------------------------------------------------- OPRF + DLEQ
static void TestOprf() {
    auto key = oprf::KeyGen(), other = oprf::KeyGen();
    std::vector<std::string> items;
    for (int i = 0; i < 100; ++i) items.push_back(RandomPhone(rng));
    oprf::ClientState st;
    Bytes req = oprf::Blind(items, 1024, st);
    CHECK(req.size() == 1024 * 32);
    Bytes resp = oprf::EvalBlinded(key, req);
    std::vector<u128> ys;
    CHECK(oprf::Finalize(items, st, key.K, req, resp, 66, ys));
    for (size_t i = 0; i < items.size(); ++i) CHECK(ys[i] == oprf::Evaluate(key, items[i], 66));
    CHECK(oprf::Evaluate(key, items[0], 66) != oprf::Evaluate(other, items[0], 66));
    // blinding: the same contact gives a fresh, unlinkable request point every time
    oprf::ClientState st2;
    Bytes req2 = oprf::Blind(items, 1024, st2);
    CHECK(memcmp(req.data(), req2.data(), 32) != 0);
    // DLEQ soundness checks
    std::vector<u128> junk;
    CHECK(!oprf::Finalize(items, st, other.K, req, resp, 66, junk));  // wrong public key
    Bytes bad = resp;  // one answer computed with a different key
    Bytes alt = oprf::EvalBlinded(other, req);
    memcpy(&bad[32 * 5], &alt[32 * 5], 32);
    CHECK(!oprf::Finalize(items, st, key.K, req, bad, 66, junk));
    Bytes badProof = resp;
    badProof[badProof.size() - 1] ^= 1;
    CHECK(!oprf::Finalize(items, st, key.K, req, badProof, 66, junk));
    bool threw = false;
    try { oprf::Blind(std::vector<std::string>(1025, "+15550000000"), 1024, st); } catch (...) { threw = true; }
    CHECK(threw);
}

// ---------------------------------------------------------------- end to end
struct World {
    Params P;
    std::vector<std::string> S;
    std::unordered_set<std::string> Sset;
    ServerState srv;
    ClientHE client;
    ServerHE server;
};
static World Make(const std::string& set, size_t nS) {
    World w;
    w.P = ParamsByName(set);
    while (w.Sset.size() < nS) w.Sset.insert(RandomPhone(rng));
    w.S.assign(w.Sset.begin(), w.Sset.end());
    w.srv = ServerOffline(w.P, w.S);
    w.client = ClientSetup(w.P);
    w.server = ServerLoadSetup(SerializeSetup(w.client));
    return w;
}
static std::vector<std::string> ClientSet(World& w, size_t n, size_t overlap) {
    std::vector<std::string> C;
    std::unordered_set<std::string> used;
    while (C.size() < overlap) { auto& s = w.S[rng() % w.S.size()]; if (used.insert(s).second) C.push_back(s); }
    while (C.size() < n) { auto x = RandomPhone(rng); if (!w.Sset.count(x) && used.insert(x).second) C.push_back(x); }
    std::shuffle(C.begin(), C.end(), rng);
    return C;
}
static bool Exact(World& w, const std::vector<std::string>& C, Diag* d = nullptr) {
    QueryResult q = RunQuery(w.P, w.srv, w.server, w.client, C, d, rng());
    bool ok = q.oprfVerified;
    for (size_t i = 0; i < C.size(); ++i) ok &= q.member[i] == (w.Sset.count(C[i]) > 0);
    return ok;
}

static World* g_T = nullptr;
static void TestEndToEndCases() {
    World& w = *g_T;
    CHECK(Exact(w, ClientSet(w, 1024, 300)));   // typical
    CHECK(Exact(w, ClientSet(w, 1024, 0)));     // empty intersection
    CHECK(Exact(w, ClientSet(w, 1024, 1024)));  // client set contained in S
    CHECK(Exact(w, ClientSet(w, 1, 1)));        // single contact, padded to 1024
    CHECK(Exact(w, ClientSet(w, 37, 5)));       // small odd size
}

static void TestMaskingAndFlooding() {
    World& w = *g_T;
    auto C = ClientSet(w, 500, 100);
    // reproduce the client side to look at raw decrypted slots
    std::vector<std::vector<u64>> slots[2];
    CuckooTable T;
    for (int run = 0; run < 2; ++run) {
        oprf::ClientState st;
        Bytes req = oprf::Blind(C, w.P.clientMax, st);
        Bytes resp = oprf::EvalBlinded(w.srv.key, req);
        std::vector<u128> ys;
        CHECK(oprf::Finalize(C, st, w.srv.key.K, req, resp, w.P.sigma, ys));
        std::mt19937_64 r(99);  // same cuckoo layout both runs
        CHECK(CuckooInsert(ys, w.P, T, r));
        Timings tm;
        Diag d;
        Bytes ans = ServerAnswer(w.server, w.srv.db, ClientQuery(w.client, w.P, T), tm, &d);
        ClientDecode(w.client, w.P, T, ans, C.size(), &slots[run]);
        // flooding: width exceeds the evaluation noise by >= 40 bits + log2 N (smudging bound <= 2^-40)
        double noise = 0;
        for (auto& c : d.preFlood) noise = std::max(noise, NoiseLog2(w.client, c));
        CHECK(d.floodLog2B - noise - w.P.logBins >= 40);
    }
    size_t differ = 0, nonmember = 0;
    for (u64 b = 0; b < w.P.bins(); ++b) {
        if (T.owner[b] < 0) continue;
        bool member = w.Sset.count(C[T.owner[b]]) > 0;
        for (uint32_t p = 0; p < w.P.partitions; ++p) {
            if (!member) {
                CHECK(slots[0][p][b] != 0 && slots[1][p][b] != 0);
                ++nonmember;
                differ += slots[0][p][b] != slots[1][p][b];
            }
        }
    }
    CHECK(nonmember > 0 && differ == nonmember);  // fresh mask every query: nothing repeats
}

// Records the OpenFHE 1.6.1 plaintext-modulus ceiling that forced t down from the 55-bit design value.
static int DecryptErrors(u64 t, uint32_t depth) {
    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> p;
    p.SetPlaintextModulus(t);
    p.SetMultiplicativeDepth(depth);
    p.SetRingDim(16384);
    p.SetSecurityLevel(lbcrypto::HEStd_NotSet);  // only decryption correctness is tested here; 55-bit t needs N=2^15 for 128 bits
    auto cc = lbcrypto::GenCryptoContext(p);
    cc->Enable(lbcrypto::PKE);
    cc->Enable(lbcrypto::LEVELEDSHE);
    auto k = cc->KeyGen();
    std::vector<int64_t> a(16384);
    for (auto& x : a) x = rng() % t;
    lbcrypto::Plaintext pt;
    cc->Decrypt(k.secretKey, cc->Encrypt(k.publicKey, cc->MakePackedPlaintext(a)), &pt);
    pt->SetLength(16384);
    int bad = 0;
    for (int i = 0; i < 16384; ++i) {
        int64_t x = pt->GetPackedValue()[i] % (int64_t)t;
        bad += (x < 0 ? x + (int64_t)t : x) != a[i];
    }
    return bad;
}
static void TestPlaintextModulusCeiling() {
    Params P = ParamsByName("A");
    CHECK(DecryptErrors(P.t, P.multDepth) == 0);  // chosen t (2^49 + ...) decrypts exactly at depth 5
    // informational: the Part 2 value (55-bit) and a prime just below 2^50 do not
    int bad55 = DecryptErrors(18014398510661633ULL, P.multDepth), bad50 = DecryptErrors(1125899904679937ULL, P.multDepth);
    std::cout << "    info: wrong slots out of 16384 at depth 5: t=2^54+... -> " << bad55 << ", t=2^50-... -> " << bad50
              << ", chosen t -> 0\n";
}

static void TestParameterSecurity() {
    for (auto n : {"A", "B", "C", "T"}) {
        Params P = ParamsByName(n);
        ClientHE c = ClientSetup(P);
        CHECK(c.cc->GetRingDimension() == P.bins());
        CHECK(Log2Q(c.cc) <= MaxLogQ128(c.cc->GetRingDimension()));
        CHECK(P.capacity() * 1.0 > 3.0 * P.serverMax / P.bins());
    }
}

static void TestDesignParamsEndToEnd() {
    for (auto n : {"A", "B"}) {
        World w = Make(n, 1u << 16);
        Diag d;
        CHECK(Exact(w, ClientSet(w, 1024, 200), &d));
        double noise = 0;
        for (auto& c : d.preFlood) noise = std::max(noise, NoiseLog2(w.client, c));
        CHECK(d.floodLog2B - noise - w.P.logBins >= 40);
        std::cout << "    set " << n << ": flood width 2^" << d.floodLog2B << ", noise 2^" << noise << "\n";
    }
}

int main(int argc, char** argv) {
    oprf::Init();
    bool quick = argc > 1 && std::string(argv[1]) == "--quick";
    Run("encoding: (bin, value) is injective, values in range", TestEncodingInvertible);
    Run("cuckoo hashing: 1024 items placed exactly once (50 reps)", TestCuckoo);
    Run("interpolation: members are roots, non-members are not", TestInterpolation);
    Run("bin overflow is detected", TestOverflowRejected);
    Run("OPRF: correctness, blinding, DLEQ rejects bad keys/answers/proofs", TestOprf);
    Run("OpenFHE plaintext-modulus ceiling: chosen t exact, 55-bit t fails", TestPlaintextModulusCeiling);
    Run("parameters: N matches bins, log2 Q within 128-bit HE-standard bound", TestParameterSecurity);
    World T = Make("T", 1u << 14);
    g_T = &T;
    Run("end-to-end (set T): 5 client-set shapes give the exact intersection", TestEndToEndCases);
    Run("masking fresh per query; flooding width >= noise + 40 + log2 N", TestMaskingAndFlooding);
    if (!quick) Run("end-to-end with design parameters (sets A, B)", TestDesignParamsEndToEnd);
    std::cout << (g_checks - g_fail) << "/" << g_checks << " checks passed\n";
    return g_fail ? 1 : 0;
}
