// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/net/doh_resolver.hpp"

#include "fb/p2p/kademlia.hpp"   // node_id_from_pubkey

#include <array>
#include <cctype>
#include <sstream>
#include <string>

#if FB_HAVE_OPENSSL
#  include "fb/net/tls_client.hpp"
#endif

namespace fb::net {

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

std::vector<DohEndpoint> default_doh_endpoints() {
    return {
        {"cloudflare-dns.com", 443, "/dns-query", {}},
        {"dns.google",         443, "/resolve",   {}},
        {"dns.quad9.net",      443, "/dns-query", {}},
    };
}

// ---------------------------------------------------------------------------
// Hex decoder for the ed25519:<hex32> prefix
// ---------------------------------------------------------------------------

namespace {

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::optional<std::vector<std::uint8_t>>
hex_decode(std::string_view s, std::size_t expected_bytes) {
    if (s.size() != expected_bytes * 2) return std::nullopt;
    std::vector<std::uint8_t> out(expected_bytes);
    for (std::size_t i = 0; i < expected_bytes; ++i) {
        const int hi = hex_nibble(s[i * 2]);
        const int lo = hex_nibble(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return out;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
        s.remove_suffix(1);
    }
    return s;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public: parse one TXT body
// ---------------------------------------------------------------------------

std::optional<fb::p2p::PeerInfo>
parse_finbit_txt(std::string_view txt_body) {
    txt_body = trim(txt_body);
    constexpr std::string_view kMagic = "fb1 ";
    if (txt_body.size() <= kMagic.size() ||
        txt_body.substr(0, kMagic.size()) != kMagic) {
        return std::nullopt;
    }
    auto rest = trim(txt_body.substr(kMagic.size()));

    // Token 1: "ed25519:<hex32>"
    const auto space = rest.find(' ');
    if (space == std::string_view::npos) return std::nullopt;
    auto key_tok = rest.substr(0, space);
    constexpr std::string_view kKp = "ed25519:";
    if (key_tok.size() <= kKp.size() ||
        key_tok.substr(0, kKp.size()) != kKp) {
        return std::nullopt;
    }
    auto pub = hex_decode(key_tok.substr(kKp.size()), 32);
    if (!pub) return std::nullopt;

    // Token 2 (rest): the address. Any non-empty string is valid;
    // schema validation happens at dial time.
    auto addr = trim(rest.substr(space + 1));
    if (addr.empty()) return std::nullopt;

    fb::p2p::PeerInfo info;
    info.id     = fb::p2p::node_id_from_pubkey(
                       std::span<const std::uint8_t>(pub->data(), pub->size()));
    info.pubkey = *pub;
    info.addr.assign(addr.begin(), addr.end());
    return info;
}

// ---------------------------------------------------------------------------
// Public: parse application/dns-json body (Cloudflare/Google/Quad9)
// ---------------------------------------------------------------------------

namespace {

// Walk an object body and return (type_int, data_string) if both
// "type":N and "data":"..." appear at depth 1 within. Returns nullopt
// if either is missing. obj_body should be the slice BETWEEN the
// outer `{` and `}` exclusive.
struct ObjFields {
    int         type = -1;
    std::string data;
    bool        has_data = false;
};

// Scan one object's body for top-level (depth-0 within the object)
// occurrences of "type":N and "data":"...". Strings inside nested
// `{...}` or `[...]` are ignored.
ObjFields scan_object_fields(std::string_view body) {
    ObjFields out;
    std::size_t i      = 0;
    int         depth  = 0;
    bool        in_str = false;
    bool        esc    = false;

    auto skip_ws_colon = [&]() {
        while (i < body.size() &&
               (std::isspace(static_cast<unsigned char>(body[i])) ||
                body[i] == ':')) ++i;
    };

    while (i < body.size()) {
        const char c = body[i];
        if (in_str) {
            if (esc)          { esc = false; ++i; continue; }
            if (c == '\\')    { esc = true;  ++i; continue; }
            if (c == '"')     { in_str = false; ++i; continue; }
            ++i; continue;
        }
        if (c == '"') {
            // Possible key at depth 0.
            if (depth == 0) {
                // Match `"type"` or `"data"` keys exactly.
                if (body.substr(i, 6) == "\"type\"") {
                    i += 6;
                    skip_ws_colon();
                    std::string num;
                    while (i < body.size() &&
                           std::isdigit(static_cast<unsigned char>(body[i]))) {
                        num.push_back(body[i++]);
                    }
                    if (!num.empty()) {
                        try { out.type = std::stoi(num); } catch (...) {}
                    }
                    continue;
                }
                if (body.substr(i, 6) == "\"data\"") {
                    i += 6;
                    skip_ws_colon();
                    if (i < body.size() && body[i] == '"') {
                        ++i;
                        std::string s;
                        bool de = false;
                        while (i < body.size()) {
                            const char d = body[i++];
                            if (de) {
                                switch (d) {
                                    case '"':  s.push_back('"');  break;
                                    case '\\': s.push_back('\\'); break;
                                    case '/':  s.push_back('/');  break;
                                    case 'n':  s.push_back('\n'); break;
                                    case 't':  s.push_back('\t'); break;
                                    case 'r':  s.push_back('\r'); break;
                                    default:   s.push_back(d);    break;
                                }
                                de = false; continue;
                            }
                            if (d == '\\') { de = true;  continue; }
                            if (d == '"')  break;
                            s.push_back(d);
                        }
                        // Strip TXT outer character-string quotes.
                        if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
                            s = s.substr(1, s.size() - 2);
                        }
                        out.data     = std::move(s);
                        out.has_data = true;
                    }
                    continue;
                }
            }
            // Skip over arbitrary string value.
            in_str = true; ++i; continue;
        }
        if (c == '{' || c == '[') { ++depth; ++i; continue; }
        if (c == '}' || c == ']') { --depth; ++i; continue; }
        ++i;
    }
    return out;
}

// Find the body of the "Answer" array in the JSON, then enumerate
// each top-level `{...}` object inside it. For each, run
// scan_object_fields and keep the data string when type == 16 (TXT).
std::vector<std::string> extract_txt_data_values(std::string_view body) {
    std::vector<std::string> out;

    // Locate "Answer" key (case-sensitive — DoH JSON spec is fixed).
    const auto ans_key = body.find("\"Answer\"");
    if (ans_key == std::string_view::npos) return out;
    auto p = body.find('[', ans_key);
    if (p == std::string_view::npos) return out;
    ++p;  // step past '['

    // Walk objects inside the array.
    int  depth  = 0;
    bool in_str = false;
    bool esc    = false;
    while (p < body.size()) {
        const char c = body[p];
        if (in_str) {
            if (esc)        { esc = false; ++p; continue; }
            if (c == '\\')  { esc = true;  ++p; continue; }
            if (c == '"')   { in_str = false; ++p; continue; }
            ++p; continue;
        }
        if (c == '"') { in_str = true; ++p; continue; }
        if (c == ']' && depth == 0) break;  // end of Answer array
        if (c == '{') {
            // Find matching '}'.
            const std::size_t start = p + 1;
            int d2 = 1;
            bool s2 = false;
            bool e2 = false;
            std::size_t j = start;
            for (; j < body.size() && d2 > 0; ++j) {
                const char d = body[j];
                if (s2) {
                    if (e2)       { e2 = false; continue; }
                    if (d == '\\'){ e2 = true;  continue; }
                    if (d == '"') { s2 = false; continue; }
                    continue;
                }
                if (d == '"') { s2 = true; continue; }
                if (d == '{' || d == '[') { ++d2; continue; }
                if (d == '}' || d == ']') { --d2; continue; }
            }
            if (d2 != 0) break;  // unbalanced
            std::string_view inner = body.substr(start, j - 1 - start);
            auto fields = scan_object_fields(inner);
            if (fields.type == 16 && fields.has_data) {
                out.push_back(std::move(fields.data));
            }
            p = j;  // past the matching '}'
            continue;
        }
        ++p;
    }
    return out;
}

}  // namespace

std::vector<fb::p2p::PeerInfo>
parse_dns_json(std::string_view body) {
    std::vector<fb::p2p::PeerInfo> out;
    for (auto& txt : extract_txt_data_values(body)) {
        if (auto info = parse_finbit_txt(txt)) {
            out.push_back(std::move(*info));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Network: GET https://endpoint.host:endpoint.port/path?name=Q&type=TXT
// ---------------------------------------------------------------------------

#if FB_HAVE_OPENSSL

namespace {

std::string url_encode(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (std::isalnum(u) || c == '.' || c == '-' || c == '_' || c == '~') {
            out.push_back(c);
        } else {
            static const char hex[] = "0123456789ABCDEF";
            out.push_back('%');
            out.push_back(hex[(u >> 4) & 0xf]);
            out.push_back(hex[u & 0xf]);
        }
    }
    return out;
}

// Split HTTP response into (status_code, headers_blob, body). Returns
// status=0 on parse failure.
struct HttpResponse {
    int          status = 0;
    std::string  body;
};
HttpResponse parse_http_response(std::string_view raw) {
    HttpResponse r;
    const auto first_nl = raw.find("\r\n");
    if (first_nl == std::string_view::npos) return r;
    auto status_line = raw.substr(0, first_nl);
    // "HTTP/1.1 200 OK"
    const auto sp1 = status_line.find(' ');
    if (sp1 == std::string_view::npos) return r;
    const auto sp2 = status_line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return r;
    try {
        r.status = std::stoi(std::string(status_line.substr(sp1 + 1, sp2 - sp1 - 1)));
    } catch (...) { return r; }
    const auto body_start = raw.find("\r\n\r\n");
    if (body_start == std::string_view::npos) return r;
    r.body.assign(raw.substr(body_start + 4));
    return r;
}

}  // namespace

std::vector<fb::p2p::PeerInfo>
resolve_finbit_bootstrap(
    const DohEndpoint& endpoint,
    std::string_view query_name,
    int timeout_ms) {
    try {
        TlsClient tls;
        TlsClientOptions opts;
        opts.sni_hostname = endpoint.host;
        // Tier-4: the DoH request always goes to a big public provider
        // (Cloudflare/Google/Quad9) over 443 — present a Chrome JA3 so
        // it blends in with ordinary browser DNS-over-HTTPS traffic.
        opts.tls_fingerprint = TlsFingerprint::kChrome;
        // DoH endpoints use real certs from public CAs — the system
        // bundle validates them. No insecure_skip_verify here.
        if (!endpoint.pinned_sha256.empty() &&
            endpoint.pinned_sha256.size() == 32) {
            // expected_peer_pubkey is for our own ed25519 pinning
            // and doesn't apply to RSA/ECDSA DoH leaf certs; pinning
            // by full-cert SHA-256 would need a new option. Skip
            // for v1; the system CA bundle is the trust root.
        }
        tls.connect(endpoint.host, endpoint.port, opts);

        std::ostringstream req;
        req << "GET " << endpoint.path
            << "?name=" << url_encode(query_name)
            << "&type=TXT"
            << " HTTP/1.1\r\n"
            << "Host: " << endpoint.host << "\r\n"
            << "Accept: application/dns-json\r\n"
            << "User-Agent: FinBit-DoH/1\r\n"
            << "Connection: close\r\n"
            << "\r\n";
        const std::string req_str = req.str();
        tls.blocking_send_all(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(req_str.data()),
            req_str.size()));

        // Drain the response. Cap the total budget; a runaway DoH
        // server should not hang the bootstrap.
        std::string raw;
        std::array<std::uint8_t, 8192> buf{};
        // Single blocking read with the whole timeout budget. On
        // Connection: close the server writes everything then
        // half-closes; blocking_read returns 0.
        while (true) {
            const auto n = tls.blocking_read(
                std::span<std::uint8_t>(buf.data(), buf.size()),
                timeout_ms);
            if (n == 0) break;
            raw.append(reinterpret_cast<const char*>(buf.data()), n);
            if (raw.size() > 256 * 1024) break;  // sanity cap
        }
        tls.close();

        auto parsed = parse_http_response(raw);
        if (parsed.status != 200) return {};
        return parse_dns_json(parsed.body);
    } catch (...) {
        // Network failures, TLS errors, bad responses — all swallow
        // and return empty. The caller falls through to the next
        // endpoint.
        return {};
    }
}

std::vector<fb::p2p::PeerInfo>
resolve_finbit_bootstrap_default(
    std::string_view query_name,
    int per_endpoint_timeout_ms) {
    for (const auto& ep : default_doh_endpoints()) {
        auto peers = resolve_finbit_bootstrap(
            ep, query_name, per_endpoint_timeout_ms);
        if (!peers.empty()) return peers;
    }
    return {};
}

#else   // FB_HAVE_OPENSSL == 0

std::vector<fb::p2p::PeerInfo>
resolve_finbit_bootstrap(const DohEndpoint&, std::string_view, int) {
    return {};
}

std::vector<fb::p2p::PeerInfo>
resolve_finbit_bootstrap_default(std::string_view, int) {
    return {};
}

#endif

}  // namespace fb::net
