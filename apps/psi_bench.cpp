// Benchmark: full protocol (offline + setup + online) for one parameter set, compared with two
// non-private baselines. Writes one JSON object to --out.
//   psi_bench --set A --trials 5 --client 1024 --overlap 256 [--server N] --out results/A.json
#include <sodium.h>
#include <omp.h>
#include <sys/resource.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <unordered_set>

#include "protocol.h"

using namespace psi;

static std::string Arg(int argc, char** argv, const std::string& k, const std::string& d) {
    for (int i = 1; i + 1 < argc; ++i)
        if (argv[i] == k) return argv[i + 1];
    return d;
}

int main(int argc, char** argv) {
    oprf::Init();
    Params P = ParamsByName(Arg(argc, argv, "--set", "A"));
    int trials = std::stoi(Arg(argc, argv, "--trials", "5"));
    size_t nC = std::stoul(Arg(argc, argv, "--client", "1024"));
    size_t overlap = std::stoul(Arg(argc, argv, "--overlap", "256"));
    size_t nS = std::stoull(Arg(argc, argv, "--server", std::to_string(P.serverMax)));
    std::string out = Arg(argc, argv, "--out", "results/" + P.name + ".json");
    std::mt19937_64 rng(std::stoull(Arg(argc, argv, "--seed", "2026")));
    std::cerr << "[" << P.name << "] |S|=" << nS << " |C|=" << nC << " overlap=" << overlap << " trials=" << trials
              << "\n";

    // ---- data
    std::unordered_set<std::string> Sset;
    Sset.reserve(nS * 2);
    while (Sset.size() < nS) Sset.insert(RandomPhone(rng));
    std::vector<std::string> S(Sset.begin(), Sset.end());

    // ---- Phase 0: server offline
    ServerState srv = ServerOffline(P, S);
    std::cerr << "  offline: oprf " << srv.tm["offline_oprf"] << " s, hash+interp " << srv.tm["offline_hash_interpolate"]
              << " s, max bin load " << srv.db.maxLoad << "/" << P.capacity() << "\n";

    // ---- Phase 1: client setup
    double t0 = Now();
    ClientHE client = ClientSetup(P);
    double tKeygen = Now() - t0;
    SetupMsg setup = SerializeSetup(client);
    t0 = Now();
    ServerHE server = ServerLoadSetup(setup);
    double tLoad = Now() - t0;

    std::ostringstream js;
    js.precision(6);
    js << "{\n\"set\": \"" << P.name << "\", \"server_size\": " << nS << ", \"client_size\": " << nC
       << ", \"overlap\": " << overlap << ", \"trials\": " << trials << ",\n";
    js << "\"params\": {\"N\": " << client.cc->GetRingDimension() << ", \"log2Q\": " << Log2Q(client.cc)
       << ", \"maxLog2Q_128\": " << MaxLogQ128(client.cc->GetRingDimension()) << ", \"t_bits\": " << std::log2((double)P.t)
       << ", \"partitions\": " << P.partitions << ", \"degree\": " << P.degree << ", \"powers\": " << P.numPowers()
       << ", \"multDepth\": " << P.multDepth << ", \"keepTowers\": " << P.keepTowers
       << ", \"towers\": " << client.cc->GetCryptoParameters()->GetElementParams()->GetParams().size()
       << ", \"bins\": " << P.bins() << ", \"capacity\": " << P.capacity() << ", \"max_load\": " << srv.db.maxLoad
       << ", \"mean_load\": " << srv.db.meanLoad << "},\n";
    js << "\"offline\": {\"oprf_s\": " << srv.tm["offline_oprf"]
       << ", \"hash_interpolate_s\": " << srv.tm["offline_hash_interpolate"] << "},\n";
    js << "\"setup\": {\"keygen_s\": " << tKeygen << ", \"server_load_s\": " << tLoad
       << ", \"context_B\": " << setup.context.size() << ", \"public_key_B\": " << setup.publicKey.size()
       << ", \"relin_key_B\": " << setup.relinKey.size() << "},\n";

    // ---- online trials
    std::vector<std::string> keys;
    std::map<std::string, std::vector<double>> T, Z;
    std::vector<double> plainT, hashT;
    double plainUp = 0, plainDown = 0, hashUp = 0, hashDown = 0, plainBuild = 0, hashBuild = 0;
    int correct = 0, fp = 0, fn = 0;
    double budgetPre = 0, noisePreFlood = 0, floodBits = 0, logQp = 0, ctQueryB = 0, ctRespB = 0;
    for (int tr = 0; tr < trials; ++tr) {
        // client set: `overlap` contacts drawn from S, the rest guaranteed not in S
        std::vector<std::string> C;
        std::unordered_set<std::string> used;
        while (C.size() < std::min(overlap, nC)) {
            auto& s = S[rng() % S.size()];
            if (used.insert(s).second) C.push_back(s);
        }
        while (C.size() < nC) {
            auto x = RandomPhone(rng);
            if (!Sset.count(x) && used.insert(x).second) C.push_back(x);
        }
        std::shuffle(C.begin(), C.end(), rng);
        Diag diag;
        QueryResult q = RunQuery(P, srv, server, client, C, tr == 0 ? &diag : nullptr, rng());
        BaselineResult pb = PlaintextBaseline(S, C, tr == 0 ? &plainBuild : nullptr);
        BaselineResult hb = HashedBaseline(S, C, tr == 0 ? &hashBuild : nullptr);
        plainT.push_back(pb.seconds); hashT.push_back(hb.seconds);
        plainUp = pb.upload; plainDown = pb.download; hashUp = hb.upload; hashDown = hb.download;
        bool ok = q.member == pb.member && hb.member == pb.member;
        for (size_t i = 0; i < C.size(); ++i) {
            fp += q.member[i] && !pb.member[i];
            fn += !q.member[i] && pb.member[i];
        }
        correct += ok;
        double online = 0;
        for (auto& [k, v] : q.tm) {
            T[k].push_back(v);
            if (k != "server_ct_mults") online += v;
        }
        T["online_total"].push_back(online);
        for (auto& [k, v] : q.sizes) Z[k].push_back(v);
        if (tr == 0) {
            budgetPre = 1e9;
            for (auto& c : diag.preSwitch) budgetPre = std::min(budgetPre, NoiseBudget(client, c));
            noisePreFlood = 0;
            for (auto& c : diag.preFlood) noisePreFlood = std::max(noisePreFlood, NoiseLog2(client, c));
            floodBits = diag.floodLog2B;
            logQp = std::log2(diag.preFlood[0]->GetElements()[0].GetModulus().ConvertToDouble());
            ctQueryB = Z["he_query"][0] / P.numPowers();
            ctRespB = Z["he_response"][0] / P.partitions;
        }
        std::cerr << "  trial " << tr << ": online " << online << " s, powers " << q.tm["server_powers"]
                  << " s, poly " << q.tm["server_poly_eval"] << " s, correct=" << ok << "\n";
    }
    auto med = [](std::vector<double> v) {
        std::sort(v.begin(), v.end());
        return v.empty() ? 0.0 : (v.size() % 2 ? v[v.size() / 2] : 0.5 * (v[v.size() / 2 - 1] + v[v.size() / 2]));
    };
    auto mn = [](const std::vector<double>& v) { return *std::min_element(v.begin(), v.end()); };
    auto mx = [](const std::vector<double>& v) { return *std::max_element(v.begin(), v.end()); };
    js << "\"online_median_s\": {";
    bool first = true;
    for (auto& [k, v] : T) { js << (first ? "" : ", ") << "\"" << k << "\": " << med(v); first = false; }
    js << "},\n\"online_min_s\": {\"online_total\": " << mn(T["online_total"]) << "}, \"online_max_s\": {\"online_total\": "
       << mx(T["online_total"]) << "},\n";
    js << "\"sizes_B\": {";
    first = true;
    for (auto& [k, v] : Z) { js << (first ? "" : ", ") << "\"" << k << "\": " << med(v); first = false; }
    js << ", \"query_ct\": " << ctQueryB << ", \"response_ct\": " << ctRespB << "},\n";
    js << "\"noise\": {\"budget_before_switch_bits\": " << budgetPre << ", \"log2Q_after_switch\": " << logQp
       << ", \"log2_noise_before_flood\": " << noisePreFlood << ", \"log2_flood_width\": " << floodBits
       << ", \"log2_stat_distance_bound\": " << (std::log2((double)P.bins()) + noisePreFlood - floodBits) << "},\n";
    js << "\"correctness\": {\"trials_correct\": " << correct << ", \"false_positives\": " << fp
       << ", \"false_negatives\": " << fn << "},\n";
    js << "\"baseline_plain\": {\"median_s\": " << med(plainT) << ", \"build_s\": " << plainBuild
       << ", \"upload_B\": " << plainUp << ", \"download_B\": " << plainDown << "},\n";
    js << "\"baseline_sha256\": {\"median_s\": " << med(hashT) << ", \"build_s\": " << hashBuild
       << ", \"upload_B\": " << hashUp << ", \"download_B\": " << hashDown
       << ", \"hashes_per_s\": " << (hashBuild > 0 ? nS / hashBuild : 0) << "},\n";
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    js << "\"peak_rss_MB\": " << ru.ru_maxrss / 1024.0 << ", \"threads\": " << omp_get_max_threads() << "\n}\n";
    std::ofstream(out) << js.str();
    std::cerr << "  wrote " << out << " (" << correct << "/" << trials << " trials correct)\n";
    return correct == trials ? 0 : 1;
}
