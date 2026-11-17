// 2HashDH OPRF over ristretto255 (libsodium) with a batched Chaum-Pedersen DLEQ proof.
//   F_k(x) = H2(x, H1(x)^k),  H1 = ristretto255 hash-to-group of SHA-512, H2 = SHA-256 truncated.
// Follows the structure of RFC 9497 (OPRF/VOPRF mode) but is not byte-compatible with it.
#include <sodium.h>

#include <cstring>
#include <stdexcept>

#include "psi.h"

namespace psi::oprf {

static const char* kH1 = "CYB599-PSI-H1";
static const char* kH2 = "CYB599-PSI-H2";
static const char* kDLEQ = "CYB599-PSI-DLEQ";

void Init() {
    if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");
}

static Point H1(const std::string& x) {
    uint8_t h[64];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, (const uint8_t*)kH1, strlen(kH1));
    crypto_hash_sha512_update(&st, (const uint8_t*)x.data(), x.size());
    crypto_hash_sha512_final(&st, h);
    Point P;
    crypto_core_ristretto255_from_hash(P.data(), h);
    return P;
}

static u128 H2(const std::string& x, const Point& u, uint32_t sigma) {
    uint8_t h[32];
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, (const uint8_t*)kH2, strlen(kH2));
    uint64_t len = x.size();
    crypto_hash_sha256_update(&st, (const uint8_t*)&len, 8);
    crypto_hash_sha256_update(&st, (const uint8_t*)x.data(), x.size());
    crypto_hash_sha256_update(&st, u.data(), 32);
    crypto_hash_sha256_final(&st, h);
    u128 y = 0;
    for (int i = 0; i < 16; ++i) y = (y << 8) | h[i];
    return y & ((((u128)1) << sigma) - 1);
}

static Scalar HashToScalar(const std::vector<const uint8_t*>& parts, const std::vector<size_t>& lens) {
    uint8_t h[64];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, (const uint8_t*)kDLEQ, strlen(kDLEQ));
    for (size_t i = 0; i < parts.size(); ++i) crypto_hash_sha512_update(&st, parts[i], lens[i]);
    crypto_hash_sha512_final(&st, h);
    Scalar s;
    crypto_core_ristretto255_scalar_reduce(s.data(), h);
    return s;
}

static Point Mul(const Scalar& s, const Point& P) {
    Point R;
    if (crypto_scalarmult_ristretto255(R.data(), s.data(), P.data()) != 0)
        throw std::runtime_error("scalarmult produced identity / invalid point");
    return R;
}
static Point Add(const Point& A, const Point& B) {
    Point R;
    crypto_core_ristretto255_add(R.data(), A.data(), B.data());
    return R;
}

ServerKey KeyGen() {
    ServerKey key;
    crypto_core_ristretto255_scalar_random(key.k.data());
    crypto_scalarmult_ristretto255_base(key.K.data(), key.k.data());
    return key;
}

u128 Evaluate(const ServerKey& key, const std::string& x, uint32_t sigma) { return H2(x, Mul(key.k, H1(x)), sigma); }

Bytes Blind(const std::vector<std::string>& items, size_t padTo, ClientState& st) {
    if (items.size() > padTo) throw std::runtime_error("client set larger than the public bound");
    Bytes req(32 * padTo);
    st.r.resize(items.size());
    for (size_t i = 0; i < padTo; ++i) {
        Point a;
        if (i < items.size()) {
            crypto_core_ristretto255_scalar_random(st.r[i].data());
            a = Mul(st.r[i], H1(items[i]));
        } else {
            crypto_core_ristretto255_random(a.data());  // dummy: uniform group element
        }
        memcpy(&req[32 * i], a.data(), 32);
    }
    return req;
}

// Batched DLEQ: seed = H(K, alphas, betas), d_i = H(seed, i), M = sum d_i alpha_i, Z = sum d_i beta_i,
// then a Chaum-Pedersen proof that log_g K = log_M Z, made non-interactive with Fiat-Shamir.
static Scalar Seed(const Point& K, const Bytes& alphas, const Bytes& betas) {
    return HashToScalar({K.data(), alphas.data(), betas.data()}, {32, alphas.size(), betas.size()});
}
static Point Combine(const Scalar& seed, const uint8_t* pts, size_t n) {
    Point acc{};
    bool first = true;
    for (size_t i = 0; i < n; ++i) {
        uint64_t idx = i;
        Scalar d = HashToScalar({seed.data(), (const uint8_t*)&idx}, {32, 8});
        Point P;
        memcpy(P.data(), pts + 32 * i, 32);
        Point Q = Mul(d, P);
        acc = first ? Q : Add(acc, Q);
        first = false;
    }
    return acc;
}

Bytes EvalBlinded(const ServerKey& key, const Bytes& request) {
    size_t n = request.size() / 32;
    Bytes betas(32 * n);
    for (size_t i = 0; i < n; ++i) {
        Point a;
        memcpy(a.data(), &request[32 * i], 32);
        if (!crypto_core_ristretto255_is_valid_point(a.data())) throw std::runtime_error("invalid point in request");
        Point b = Mul(key.k, a);
        memcpy(&betas[32 * i], b.data(), 32);
    }
    Scalar seed = Seed(key.K, request, betas);
    Point M = Combine(seed, request.data(), n);
    Point Z = Mul(key.k, M);  // server knows k, so Z = M^k directly
    Scalar r, s, ck;
    crypto_core_ristretto255_scalar_random(r.data());
    Point T1, T2 = Mul(r, M);
    crypto_scalarmult_ristretto255_base(T1.data(), r.data());
    Scalar c = HashToScalar({key.K.data(), M.data(), Z.data(), T1.data(), T2.data()}, {32, 32, 32, 32, 32});
    crypto_core_ristretto255_scalar_mul(ck.data(), c.data(), key.k.data());
    crypto_core_ristretto255_scalar_sub(s.data(), r.data(), ck.data());  // s = r - c k
    Bytes resp = betas;
    resp.insert(resp.end(), c.begin(), c.end());
    resp.insert(resp.end(), s.begin(), s.end());
    return resp;
}

bool Finalize(const std::vector<std::string>& items, const ClientState& st, const Point& K, const Bytes& request,
              const Bytes& response, uint32_t sigma, std::vector<u128>& out) {
    size_t n = request.size() / 32;
    if (response.size() != 32 * n + 64) return false;
    Bytes betas(response.begin(), response.begin() + 32 * n);
    for (size_t i = 0; i < n; ++i)
        if (!crypto_core_ristretto255_is_valid_point(&betas[32 * i])) return false;
    Scalar c, s;
    memcpy(c.data(), &response[32 * n], 32);
    memcpy(s.data(), &response[32 * n + 32], 32);
    // verify: T1 = g^s K^c, T2 = M^s Z^c, c == H(K, M, Z, T1, T2)
    Scalar seed = Seed(K, request, betas);
    Point M = Combine(seed, request.data(), n);
    Point Z = Combine(seed, betas.data(), n);
    try {
        Point gs;
        crypto_scalarmult_ristretto255_base(gs.data(), s.data());
        Point T1 = Add(gs, Mul(c, K));
        Point T2 = Add(Mul(s, M), Mul(c, Z));
        Scalar c2 = HashToScalar({K.data(), M.data(), Z.data(), T1.data(), T2.data()}, {32, 32, 32, 32, 32});
        if (sodium_memcmp(c.data(), c2.data(), 32) != 0) return false;
    } catch (const std::exception&) {
        return false;
    }
    out.resize(items.size());
    for (size_t i = 0; i < items.size(); ++i) {
        Scalar rinv;
        crypto_core_ristretto255_scalar_invert(rinv.data(), st.r[i].data());
        Point b;
        memcpy(b.data(), &betas[32 * i], 32);
        out[i] = H2(items[i], Mul(rinv, b), sigma);
    }
    return true;
}
}  // namespace psi::oprf
