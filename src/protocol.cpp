#include "protocol.h"

#include <sodium.h>

#include <stdexcept>
#include <unordered_set>

namespace psi {

ServerState ServerOffline(const Params& P, const std::vector<std::string>& S) {
    ServerState st;
    st.P = P;
    double t0 = Now();
    st.key = oprf::KeyGen();
    std::vector<u128> ys(S.size());
#pragma omp parallel for schedule(static)
    for (int64_t i = 0; i < (int64_t)S.size(); ++i) ys[i] = oprf::Evaluate(st.key, S[i], P.sigma);
    st.tm["offline_oprf"] = Now() - t0;
    t0 = Now();
    st.db = BuildServerDB(ys, P);
    st.tm["offline_hash_interpolate"] = Now() - t0;
    return st;
}

QueryResult RunQuery(const Params& P, const ServerState& srv, const ServerHE& server, const ClientHE& client,
                     const std::vector<std::string>& C, Diag* diag, uint64_t seed) {
    QueryResult q;
    // ---- Phase 2: OPRF round
    double t0 = Now();
    oprf::ClientState cs;
    Bytes req = oprf::Blind(C, P.clientMax, cs);
    q.tm["client_oprf_blind"] = Now() - t0;
    t0 = Now();
    Bytes resp = oprf::EvalBlinded(srv.key, req);
    q.tm["server_oprf_eval_prove"] = Now() - t0;
    t0 = Now();
    std::vector<u128> ys;
    q.oprfVerified = oprf::Finalize(C, cs, srv.key.K, req, resp, P.sigma, ys);
    q.tm["client_oprf_verify_unblind"] = Now() - t0;
    if (!q.oprfVerified) throw std::runtime_error("DLEQ proof rejected");
    q.sizes["oprf_request"] = req.size();
    q.sizes["oprf_response"] = resp.size();
    q.sizes["dleq_proof"] = 64;

    // ---- Phase 3: HE query round
    t0 = Now();
    CuckooTable T;
    std::mt19937_64 rng(seed);
    if (!CuckooInsert(ys, P, T, rng)) throw std::runtime_error("cuckoo insertion failed");
    q.tm["client_cuckoo"] = Now() - t0;
    t0 = Now();
    Bytes query = ClientQuery(client, P, T);
    q.tm["client_encrypt_query"] = Now() - t0;
    q.sizes["he_query"] = query.size();

    Bytes answer = ServerAnswer(server, srv.db, query, q.tm, diag);
    q.sizes["he_response"] = answer.size();

    t0 = Now();
    q.member = ClientDecode(client, P, T, answer, C.size());
    q.tm["client_decrypt_decode"] = Now() - t0;
    return q;
}

BaselineResult PlaintextBaseline(const std::vector<std::string>& S, const std::vector<std::string>& C,
                                 double* buildSeconds) {
    double t0 = Now();
    std::unordered_set<std::string> set(S.begin(), S.end());
    if (buildSeconds) *buildSeconds = Now() - t0;
    BaselineResult r;
    t0 = Now();
    // client uploads raw identifiers (length-prefixed); server answers with a bitmap
    for (auto& c : C) r.upload += 1 + c.size();
    r.member.resize(C.size());
    for (size_t i = 0; i < C.size(); ++i) r.member[i] = set.count(C[i]) > 0;
    r.download = (C.size() + 7) / 8;
    r.seconds = Now() - t0;
    return r;
}

static std::string Sha256(const std::string& x) {
    unsigned char h[32];
    crypto_hash_sha256(h, (const unsigned char*)x.data(), x.size());
    return std::string((char*)h, 32);
}

BaselineResult HashedBaseline(const std::vector<std::string>& S, const std::vector<std::string>& C,
                              double* buildSeconds) {
    double t0 = Now();
    std::unordered_set<std::string> set;
    set.reserve(S.size());
    for (auto& s : S) set.insert(Sha256(s));
    if (buildSeconds) *buildSeconds = Now() - t0;
    BaselineResult r;
    t0 = Now();
    r.member.resize(C.size());
    for (size_t i = 0; i < C.size(); ++i) r.member[i] = set.count(Sha256(C[i])) > 0;
    r.upload = 32.0 * C.size();
    r.download = (C.size() + 7) / 8;
    r.seconds = Now() - t0;
    return r;
}
}  // namespace psi
