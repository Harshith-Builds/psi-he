// BFV layer: client query, server homomorphic polynomial evaluation, masking, modulus switching,
// noise flooding, client decoding. Every message crosses the client/server boundary as bytes.
#include <sodium.h>

#include <sstream>
#include <stdexcept>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "psi.h"
#include "scheme/bfvrns/bfvrns-ser.h"

using namespace lbcrypto;

namespace psi {

static Bytes ToBytes(const std::stringstream& ss) {
    std::string s = ss.str();
    return Bytes(s.begin(), s.end());
}
static std::stringstream FromBytes(const Bytes& b) {
    std::stringstream ss(std::string(b.begin(), b.end()));
    return ss;
}
static Bytes SerCts(const std::vector<Ciphertext<DCRTPoly>>& cts) {
    std::stringstream ss;
    uint32_t n = cts.size();
    ss.write((const char*)&n, 4);
    for (auto& c : cts) Serial::Serialize(c, ss, SerType::BINARY);
    return ToBytes(ss);
}
static std::vector<Ciphertext<DCRTPoly>> DesCts(const Bytes& b) {
    auto ss = FromBytes(b);
    uint32_t n;
    ss.read((char*)&n, 4);
    std::vector<Ciphertext<DCRTPoly>> cts(n);
    for (auto& c : cts) Serial::Deserialize(c, ss, SerType::BINARY);
    return cts;
}

size_t CiphertextBytes(const Ciphertext<DCRTPoly>& ct) {
    std::stringstream ss;
    Serial::Serialize(ct, ss, SerType::BINARY);
    return ss.str().size();
}
double Log2Q(const CryptoContext<DCRTPoly>& cc) {
    return std::log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble());
}
uint32_t MaxLogQ128(uint32_t N) { return StdLatticeParm::FindMaxQ(HEStd_ternary, HEStd_128_classic, N); }

ClientHE ClientSetup(const Params& P) {
    CCParams<CryptoContextBFVRNS> p;
    p.SetPlaintextModulus(P.t);
    p.SetMultiplicativeDepth(P.multDepth);
    p.SetSecurityLevel(HEStd_128_classic);
    p.SetBatchSize(P.bins());
    ClientHE c;
    c.cc = GenCryptoContext(p);
    c.cc->Enable(PKE);
    c.cc->Enable(KEYSWITCH);
    c.cc->Enable(LEVELEDSHE);
    if (c.cc->GetRingDimension() != P.bins())
        throw std::runtime_error("OpenFHE chose N=" + std::to_string(c.cc->GetRingDimension()) +
                                 " but the bin layout needs N=" + std::to_string(P.bins()));
    c.keys = c.cc->KeyGen();
    c.cc->EvalMultKeyGen(c.keys.secretKey);
    return c;
}

SetupMsg SerializeSetup(const ClientHE& c) {
    SetupMsg m;
    std::stringstream a, b, r;
    Serial::Serialize(c.cc, a, SerType::BINARY);
    Serial::Serialize(c.keys.publicKey, b, SerType::BINARY);
    CryptoContextImpl<DCRTPoly>::SerializeEvalMultKey(r, SerType::BINARY, c.keys.secretKey->GetKeyTag());
    m.context = ToBytes(a); m.publicKey = ToBytes(b); m.relinKey = ToBytes(r);
    return m;
}

ServerHE ServerLoadSetup(const SetupMsg& m) {
    ServerHE s;
    auto a = FromBytes(m.context), b = FromBytes(m.publicKey), r = FromBytes(m.relinKey);
    Serial::Deserialize(s.cc, a, SerType::BINARY);
    Serial::Deserialize(s.pk, b, SerType::BINARY);
    // In this single-process harness the client's copy of the key is already registered under the same
    // tag in OpenFHE's global key map; drop it so the server really loads the transmitted bytes.
    CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys(s.pk->GetKeyTag());
    if (!CryptoContextImpl<DCRTPoly>::DeserializeEvalMultKey(r, SerType::BINARY))
        throw std::runtime_error("could not load relinearization key");
    return s;
}

Bytes ClientQuery(const ClientHE& c, const Params& P, const CuckooTable& T) {
    std::vector<u64> x = T.value;
    std::vector<Ciphertext<DCRTPoly>> cts;
    for (uint32_t i = 0; i < P.numPowers(); ++i) {
        std::vector<int64_t> v(x.begin(), x.end());
        cts.push_back(c.cc->Encrypt(c.keys.publicKey, c.cc->MakePackedPlaintext(v)));
        for (auto& e : x) e = MulMod(e, e, P.t);  // next power x^(2^(i+1)), computed in the clear
    }
    return SerCts(cts);
}

static u64 RandNonzero(u64 t) {  // uniform in [1, t-1], cryptographic RNG, rejection sampling
    u64 mask = 1;
    while (mask < t) mask = (mask << 1) | 1;
    for (;;) {
        u64 r;
        randombytes_buf(&r, 8);
        r &= mask;
        if (r >= 1 && r < t) return r;
    }
}

// Adds uniform noise in [-2^bits, 2^bits) to the c0 component (noise flooding / smudging).
static void FloodC0(Ciphertext<DCRTPoly>& ct, uint32_t bits) {
    if (bits + 1 > 126) throw std::runtime_error("flooding width too large");
    auto el = ct->GetElements();
    DCRTPoly& c0 = el[0];
    Format orig = c0.GetFormat();
    auto params = c0.GetParams();
    uint32_t N = params->GetRingDimension();
    std::vector<__int128> u(N);
    u128 top = (u128)1 << bits;
    for (uint32_t k = 0; k < N; ++k) {
        u128 r;
        randombytes_buf(&r, 16);
        r &= (((u128)1 << (bits + 1)) - 1);
        u[k] = (__int128)r - (__int128)top;
    }
    DCRTPoly U(params, Format::COEFFICIENT, true);
    for (size_t i = 0; i < params->GetParams().size(); ++i) {
        auto tp = params->GetParams()[i];
        u64 q = tp->GetModulus().ConvertToInt();
        NativeVector vec(N, tp->GetModulus());
        for (uint32_t k = 0; k < N; ++k) {
            __int128 m = u[k] % (__int128)q;
            if (m < 0) m += q;
            vec[k] = NativeInteger((u64)m);
        }
        NativePoly poly(tp, Format::COEFFICIENT, true);
        poly.SetValues(std::move(vec), Format::COEFFICIENT);
        U.SetElementAtIndex(i, std::move(poly));
    }
    if (orig == Format::EVALUATION) U.SetFormat(Format::EVALUATION);
    c0 += U;
    ct->SetElements(std::move(el));
}

Bytes ServerAnswer(const ServerHE& s, const ServerDB& db, const Bytes& query, Timings& tm, Diag* diag) {
    const Params& P = db.P;
    const auto& cc = s.cc;
    const uint32_t D = P.degree, nb = P.bins();
    double t0 = Now();
    auto X = DesCts(query);
    if (X.size() != P.numPowers()) throw std::runtime_error("unexpected number of query ciphertexts");
    tm["server_deserialize"] = Now() - t0;

    // 1. all powers X^j, j <= D, each a balanced product of the received X^(2^i): depth ceil(log2 popcount(j))
    t0 = Now();
    std::vector<Ciphertext<DCRTPoly>> pw(D + 1);
    for (uint32_t i = 0; i < X.size(); ++i) pw[1u << i] = X[i];
    size_t mults = 0;
    for (uint32_t j = 1; j <= D; ++j) {
        if (pw[j]) continue;
        uint32_t pc = __builtin_popcount(j), half = (pc + 1) / 2, j1 = 0, seen = 0;
        for (uint32_t b = 0; b < 32 && seen < half; ++b)
            if (j >> b & 1) { j1 |= 1u << b; ++seen; }
        pw[j] = cc->EvalMult(pw[j1], pw[j - j1]);  // tensor + relinearize
        ++mults;
    }
    tm["server_powers"] = Now() - t0;
    tm["server_ct_mults"] = mults;

    // 2. per partition: R_p = sum_j (r_p * coef_{p,j}) * X^j, fresh mask r_p per slot per query
    std::vector<Ciphertext<DCRTPoly>> R;
    double tEnc = 0, tEval = 0;
    for (uint32_t p = 0; p < P.partitions; ++p) {
        double a = Now();
        std::vector<u64> r(nb);
        for (auto& v : r) v = RandNonzero(P.t);
        std::vector<Plaintext> pts(D + 1);
        for (uint32_t j = 0; j <= D; ++j) {
            const auto& cf = db.coef[size_t(p) * (D + 1) + j];
            std::vector<int64_t> m(nb);
            for (uint32_t b = 0; b < nb; ++b) m[b] = (int64_t)MulMod(r[b], cf[b], P.t);
            pts[j] = cc->MakePackedPlaintext(m);
        }
        tEnc += Now() - a;
        a = Now();
        Ciphertext<DCRTPoly> acc = cc->EvalMult(pw[1], pts[1]);
        for (uint32_t j = 2; j <= D; ++j) cc->EvalAddInPlace(acc, cc->EvalMult(pw[j], pts[j]));
        acc = cc->EvalAdd(acc, pts[0]);
        tEval += Now() - a;
        R.push_back(acc);
    }
    tm["server_encode_masked_coeffs"] = tEnc;
    tm["server_poly_eval"] = tEval;

    // 3. modulus switch to keepTowers limbs, re-randomize with Enc(0), flood c0 with wide uniform noise
    t0 = Now();
    if (diag) diag->preSwitch = R;
    for (auto& ct : R) ct = cc->Compress(ct, P.keepTowers);
    if (diag) {
        diag->preFlood.clear();
        for (auto& ct : R) diag->preFlood.push_back(ct->Clone());
    }
    for (auto& ct : R) {
        double logQp = std::log2(ct->GetElements()[0].GetModulus().ConvertToDouble());
        uint32_t bits = std::min<uint32_t>((uint32_t)std::floor(logQp - std::log2((double)P.t)) - 3, 125);  // |u| <= Q'/(8t)
        auto z = cc->Encrypt(s.pk, cc->MakePackedPlaintext(std::vector<int64_t>(nb, 0)));
        z = cc->Compress(z, P.keepTowers);
        ct = cc->EvalAdd(ct, z);
        FloodC0(ct, bits);
        if (diag) diag->floodLog2B = bits;
    }
    tm["server_switch_flood"] = Now() - t0;
    t0 = Now();
    Bytes out = SerCts(R);
    tm["server_serialize"] = Now() - t0;
    return out;
}

std::vector<bool> ClientDecode(const ClientHE& c, const Params& P, const CuckooTable& T, const Bytes& answer,
                               size_t nItems, std::vector<std::vector<u64>>* slotsOut) {
    auto R = DesCts(answer);
    std::vector<bool> in(nItems, false);
    for (auto& ct : R) {
        Plaintext pt;
        c.cc->Decrypt(c.keys.secretKey, ct, &pt);
        pt->SetLength(P.bins());
        const auto& v = pt->GetPackedValue();
        std::vector<u64> slots(P.bins());
        for (uint32_t b = 0; b < P.bins(); ++b) {
            int64_t x = v[b] % (int64_t)P.t;
            slots[b] = x < 0 ? x + P.t : x;
            if (T.owner[b] >= 0 && slots[b] == 0) in[T.owner[b]] = true;
        }
        if (slotsOut) slotsOut->push_back(std::move(slots));
    }
    return in;
}

// ---- diagnostics: exact phase noise e in c0 + c1*s = Delta*m + e (mod Q'), using the secret key
static void PhaseNoise(const ClientHE& c, const Ciphertext<DCRTPoly>& ct, double& log2e, double& log2Q) {
    const auto& el = ct->GetElements();
    if (el.size() != 2) throw std::runtime_error("expected a 2-component ciphertext");
    DCRTPoly sk = c.keys.secretKey->GetPrivateElement();
    size_t towers = el[0].GetNumOfElements();
    if (sk.GetNumOfElements() > towers) sk.DropLastElements(sk.GetNumOfElements() - towers);
    DCRTPoly v = el[0] + el[1] * sk;
    v.SetFormat(Format::COEFFICIENT);
    auto big = v.CRTInterpolate();
    BigInteger Q = big.GetModulus(), t(c.cc->GetCryptoParameters()->GetPlaintextModulus());
    BigInteger Delta = Q / t, half = Q >> 1, maxe(0);
    for (size_t i = 0; i < big.GetLength(); ++i) {
        BigInteger vi = big[i];
        BigInteger m = (vi * t + half) / Q;  // round(t v / Q)
        BigInteger dm = (Delta * m).Mod(Q);
        BigInteger e = vi >= dm ? vi - dm : vi + Q - dm;
        if (e > half) e = Q - e;
        if (e > maxe) maxe = e;
    }
    auto lg = [](const BigInteger& x) {
        if (x == BigInteger(0)) return 0.0;
        uint32_t msb = x.GetMSB();
        if (msb <= 60) return std::log2(x.ConvertToDouble());
        return std::log2((x >> (msb - 53)).ConvertToDouble()) + (msb - 53);
    };
    log2e = lg(maxe);
    log2Q = lg(Q);
}
double NoiseLog2(const ClientHE& c, const Ciphertext<DCRTPoly>& ct) {
    double e, q;
    PhaseNoise(c, ct, e, q);
    return e;
}
double NoiseBudget(const ClientHE& c, const Ciphertext<DCRTPoly>& ct) {
    double e, q;
    PhaseNoise(c, ct, e, q);
    double b = q - std::log2((double)c.cc->GetCryptoParameters()->GetPlaintextModulus()) - 1 - e;
    return b > 0 ? b : 0;
}
}  // namespace psi
