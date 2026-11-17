// Unbalanced Private Set Intersection from BFV homomorphic encryption (OpenFHE) with an
// OPRF pre-processing step (2HashDH over ristretto255) and a batched Chaum-Pedersen DLEQ proof.
// Design: CYB 599 Part 2 (Chen-Laine-Rindal CCS'17 + Chen et al. CCS'18 OPRF step).
#pragma once
#include <array>
#include <cstdint>
#include <map>
#include <random>
#include <string>
#include <vector>

#include "openfhe.h"

namespace psi {

using u64 = uint64_t;
using u128 = unsigned __int128;
using Bytes = std::vector<uint8_t>;
using lbcrypto::Ciphertext;
using lbcrypto::CryptoContext;
using lbcrypto::DCRTPoly;

// ------------------------------------------------------------------ parameters
struct Params {
    std::string name;
    uint32_t logBins = 14;      // number of hash bins = BFV slots = ring dimension N
    uint32_t partitions = 2;    // polynomials per bin on the server
    uint32_t degree = 160;      // roots per polynomial (bin capacity = partitions * degree)
    uint32_t multDepth = 4;     // depth passed to OpenFHE's BFV parameter generator
    uint32_t keepTowers = 3;    // RNS limbs kept when the response is mod-switched down
    uint32_t clientMax = 1024;  // client set is padded to this size (public)
    u64 serverMax = 1u << 20;   // server set size the parameters are provisioned for (public)
    u64 t = 562949954142209ULL;  // 50-bit prime just above 2^49, t = 1 (mod 2^16); see README on the t limit
    uint32_t sigma = 61;        // OPRF output length in bits: y_L = 47 bits so 4*y_L+i < 2^49 < t

    uint32_t bins() const { return 1u << logBins; }
    uint32_t yLBits() const { return sigma - logBins; }  // bits kept in the slot (52 for 2^14 bins)
    uint32_t numPowers() const {                          // client sends X^(2^i), i < numPowers
        uint32_t k = 0;
        while ((1u << k) <= degree) ++k;
        return k;
    }
    uint32_t capacity() const { return partitions * degree; }
};
Params ParamsByName(const std::string& name);  // "A", "B", "C", "T" (small test set)
std::vector<std::string> ParamSetNames();

// ------------------------------------------------------------------ OPRF (oprf.cpp)
namespace oprf {
using Point = std::array<uint8_t, 32>;
using Scalar = std::array<uint8_t, 32>;
struct ServerKey {
    Scalar k;
    Point K;  // K = g^k, published
};
struct ClientState {
    std::vector<Scalar> r;  // blinding scalars, one per real item
};
void Init();
ServerKey KeyGen();
u128 Evaluate(const ServerKey& key, const std::string& x, uint32_t sigma);  // F_k(x), server side
// Client: blinded request of exactly padTo points (real items first, then random points).
Bytes Blind(const std::vector<std::string>& items, size_t padTo, ClientState& st);
// Server: response = beta_1..beta_n || DLEQ proof (challenge, response) (64 bytes).
Bytes EvalBlinded(const ServerKey& key, const Bytes& request);
// Client: verifies the batched DLEQ proof, unblinds, outputs y_i = H2(x_i, H1(x_i)^k).
bool Finalize(const std::vector<std::string>& items, const ClientState& st, const Point& K,
              const Bytes& request, const Bytes& response, uint32_t sigma, std::vector<u128>& out);
}  // namespace oprf

// ------------------------------------------------------------------ hashing (hashing.cpp)
u64 BinOf(u128 y, uint32_t i, const Params& P);    // y_R xor h_i(y_L), i in {1,2,3}
u64 ValueOf(u128 y, uint32_t i, const Params& P);  // 4*y_L + i  (never 0 mod 4)
struct CuckooTable {
    std::vector<u64> value;   // per bin: stored value, 0 = empty
    std::vector<int> owner;   // per bin: index of client item, -1 = empty
};
// Returns false if insertion fails (probability negligible at 6.25% load).
bool CuckooInsert(const std::vector<u128>& ys, const Params& P, CuckooTable& T, std::mt19937_64& rng);

struct ServerDB {
    Params P;
    std::vector<std::vector<u64>> coef;  // index p*(degree+1)+j : coefficient j of P_{b,p} for all b
    size_t maxLoad = 0;
    double meanLoad = 0;
};
// Simple hashing into all 3 bins, partitioning, padding with dummy roots, interpolation.
ServerDB BuildServerDB(const std::vector<u128>& ys, const Params& P);
u64 MulMod(u64 a, u64 b, u64 m);
u64 PolyEval(const ServerDB& db, uint32_t p, uint32_t bin, u64 x);  // for tests

// ------------------------------------------------------------------ HE layer (he.cpp)
using Timings = std::map<std::string, double>;  // seconds

struct ClientHE {
    CryptoContext<DCRTPoly> cc;
    lbcrypto::KeyPair<DCRTPoly> keys;
};
struct ServerHE {
    CryptoContext<DCRTPoly> cc;
    lbcrypto::PublicKey<DCRTPoly> pk;
};
struct SetupMsg {  // sent once per device, cached by the server
    Bytes context, publicKey, relinKey;
    size_t size() const { return context.size() + publicKey.size() + relinKey.size(); }
};
struct Diag {  // filled only by tests/benchmarks; needs the secret key afterwards
    std::vector<Ciphertext<DCRTPoly>> preFlood;  // response before flooding (after mod switch)
    std::vector<Ciphertext<DCRTPoly>> preSwitch;  // response before mod switch
    double floodLog2B = 0;
};

ClientHE ClientSetup(const Params& P);
SetupMsg SerializeSetup(const ClientHE& c);
ServerHE ServerLoadSetup(const SetupMsg& m);
Bytes ClientQuery(const ClientHE& c, const Params& P, const CuckooTable& T);
Bytes ServerAnswer(const ServerHE& s, const ServerDB& db, const Bytes& query, Timings& tm, Diag* diag = nullptr);
// Returns, for each client item index 0..nItems-1, whether it is in the intersection.
std::vector<bool> ClientDecode(const ClientHE& c, const Params& P, const CuckooTable& T, const Bytes& answer,
                               size_t nItems, std::vector<std::vector<u64>>* slotsOut = nullptr);

// Diagnostics (secret key required): invariant noise budget (bits) and log2 of max phase noise.
double NoiseBudget(const ClientHE& c, const Ciphertext<DCRTPoly>& ct);
double NoiseLog2(const ClientHE& c, const Ciphertext<DCRTPoly>& ct);
size_t CiphertextBytes(const Ciphertext<DCRTPoly>& ct);
double Log2Q(const CryptoContext<DCRTPoly>& cc);
uint32_t MaxLogQ128(uint32_t N);  // HE-standard bound, uniform ternary secret, 128-bit classical

// ------------------------------------------------------------------ helpers
std::string RandomPhone(std::mt19937_64& rng);  // E.164, +1 NPA-NXX-XXXX
double Now();
}  // namespace psi
