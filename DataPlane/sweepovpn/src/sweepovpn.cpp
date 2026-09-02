// Implementation of the C ABI declared in sweepovpn.h.
//
// The only interesting part is the tun bridge. OpenVPN 3 expects to be handed a
// tun file descriptor it can read and write IP packets on. A
// NEPacketTunnelProvider has no such descriptor, so `tun_builder_establish()`
// creates a datagram socketpair, gives OpenVPN 3 one end, and keeps the other.
// A pump thread reads that end and forwards each packet to Swift; `send()`
// writes into it and OpenVPN 3 picks the packet up as if it came off a tun.

#include "sweepovpn.h"

#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ovpncli.hpp"

using namespace openvpn;

namespace {

/// JSON-escape a string. The values we emit are addresses and interface names
/// from the server's push reply, but they are still remote input, so they get
/// escaped rather than trusted to be quote-free.
std::string json_escape(const std::string &in)
{
    std::string out;
    out.reserve(in.size() + 8);
    for (const char c : in)
    {
        switch (c)
        {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20)
            {
                char buf[7];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            }
            else
            {
                out += c;
            }
        }
    }
    return out;
}

struct TunAddress
{
    std::string address;
    int prefix = 0;
    std::string gateway;
    bool ipv6 = false;
};

struct TunRoute
{
    std::string address;
    int prefix = 0;
    bool ipv6 = false;
    bool exclude = false;
};

/// Everything the server pushed, accumulated across the tun_builder_* calls and
/// emitted once at establish time.
struct TunSettings
{
    std::vector<TunAddress> addresses;
    std::vector<TunRoute> routes;
    std::vector<std::string> dns;
    std::string remote;
    std::string session_name;
    int mtu = 0;
    bool redirect_gw_v4 = false;
    bool redirect_gw_v6 = false;

    void clear() { *this = TunSettings(); }

    std::string to_json() const
    {
        std::ostringstream os;
        os << "{";
        os << "\"mtu\":" << mtu;
        os << ",\"remote\":\"" << json_escape(remote) << "\"";
        os << ",\"sessionName\":\"" << json_escape(session_name) << "\"";
        os << ",\"redirectGatewayV4\":" << (redirect_gw_v4 ? "true" : "false");
        os << ",\"redirectGatewayV6\":" << (redirect_gw_v6 ? "true" : "false");

        os << ",\"addresses\":[";
        for (size_t i = 0; i < addresses.size(); ++i)
        {
            const auto &a = addresses[i];
            if (i) os << ",";
            os << "{\"address\":\"" << json_escape(a.address) << "\""
               << ",\"prefix\":" << a.prefix
               << ",\"gateway\":\"" << json_escape(a.gateway) << "\""
               << ",\"ipv6\":" << (a.ipv6 ? "true" : "false") << "}";
        }
        os << "]";

        os << ",\"routes\":[";
        for (size_t i = 0; i < routes.size(); ++i)
        {
            const auto &r = routes[i];
            if (i) os << ",";
            os << "{\"address\":\"" << json_escape(r.address) << "\""
               << ",\"prefix\":" << r.prefix
               << ",\"ipv6\":" << (r.ipv6 ? "true" : "false")
               << ",\"exclude\":" << (r.exclude ? "true" : "false") << "}";
        }
        os << "]";

        os << ",\"dns\":[";
        for (size_t i = 0; i < dns.size(); ++i)
        {
            if (i) os << ",";
            os << "\"" << json_escape(dns[i]) << "\"";
        }
        os << "]";

        os << "}";
        return os.str();
    }
};

class SweepClient : public ClientAPI::OpenVPNClient
{
  public:
    SweepClient(sweep_ovpn_packet_cb packet_cb,
                sweep_ovpn_event_cb event_cb,
                sweep_ovpn_tun_cb tun_cb,
                sweep_ovpn_log_cb log_cb,
                void *ctx)
        : packet_cb_(packet_cb), event_cb_(event_cb), tun_cb_(tun_cb),
          log_cb_(log_cb), ctx_(ctx)
    {
    }

    ~SweepClient() override
    {
        shutdown_pump();
    }

    // MARK: - TunBuilderBase

    bool tun_builder_new() override
    {
        std::lock_guard<std::mutex> lock(settings_mutex_);
        settings_.clear();
        return true;
    }

    bool tun_builder_set_layer(int layer) override
    {
        // Layer 3 only. A tap-style layer 2 tunnel cannot be carried by
        // NEPacketTunnelProvider, which deals in IP packets.
        return layer == 3;
    }

    bool tun_builder_set_remote_address(const std::string &address, bool /*ipv6*/) override
    {
        std::lock_guard<std::mutex> lock(settings_mutex_);
        settings_.remote = address;
        return true;
    }

    bool tun_builder_add_address(const std::string &address,
                                 int prefix_length,
                                 const std::string &gateway,
                                 bool ipv6,
                                 bool /*net30*/) override
    {
        std::lock_guard<std::mutex> lock(settings_mutex_);
        settings_.addresses.push_back(TunAddress{address, prefix_length, gateway, ipv6});
        return true;
    }

    bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int /*flags*/) override
    {
        std::lock_guard<std::mutex> lock(settings_mutex_);
        settings_.redirect_gw_v4 = ipv4;
        settings_.redirect_gw_v6 = ipv6;
        return true;
    }

    bool tun_builder_add_route(const std::string &address,
                               int prefix_length,
                               int /*metric*/,
                               bool ipv6) override
    {
        std::lock_guard<std::mutex> lock(settings_mutex_);
        settings_.routes.push_back(TunRoute{address, prefix_length, ipv6, false});
        return true;
    }

    bool tun_builder_exclude_route(const std::string &address,
                                   int prefix_length,
                                   int /*metric*/,
                                   bool ipv6) override
    {
        std::lock_guard<std::mutex> lock(settings_mutex_);
        settings_.routes.push_back(TunRoute{address, prefix_length, ipv6, true});
        return true;
    }

    bool tun_builder_set_dns_options(const DnsOptions &dns) override
    {
        std::lock_guard<std::mutex> lock(settings_mutex_);
        for (const auto &entry : dns.servers)
        {
            for (const auto &addr : entry.second.addresses)
            {
                settings_.dns.push_back(addr.address);
            }
        }
        return true;
    }

    bool tun_builder_set_mtu(int mtu) override
    {
        std::lock_guard<std::mutex> lock(settings_mutex_);
        settings_.mtu = mtu;
        return true;
    }

    bool tun_builder_set_session_name(const std::string &name) override
    {
        std::lock_guard<std::mutex> lock(settings_mutex_);
        settings_.session_name = name;
        return true;
    }

    /// Hand OpenVPN 3 one end of a datagram socketpair and keep the other.
    int tun_builder_establish() override
    {
        shutdown_pump();

        int fds[2] = {-1, -1};
        if (::socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0)
        {
            log_line("socketpair failed, cannot establish tun bridge");
            return -1;
        }

        // A tunnel's worth of packets can burst; the default socket buffer is
        // small enough to drop them under load.
        const int bufsize = 512 * 1024;
        ::setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        ::setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
        ::setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        ::setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

        our_fd_.store(fds[1]);
        pump_running_.store(true);
        pump_ = std::thread([this] { pump(); });

        std::string json;
        {
            std::lock_guard<std::mutex> lock(settings_mutex_);
            json = settings_.to_json();
        }
        if (tun_cb_) tun_cb_(ctx_, json.c_str());

        // OpenVPN 3 owns fds[0] from here and closes it on teardown.
        return fds[0];
    }

    // MARK: - Client callbacks

    void event(const ClientAPI::Event &ev) override
    {
        if (event_cb_) event_cb_(ctx_, ev.name.c_str(), ev.info.c_str());
    }

    void log(const ClientAPI::LogInfo &li) override
    {
        log_line(li.text);
    }

    bool socket_protect(openvpn_io::detail::socket_type /*socket*/,
                        std::string /*remote*/,
                        bool /*ipv6*/) override
    {
        // The extension's own sockets are already outside the tunnel it
        // creates, so there is no routing loop to protect against here.
        return true;
    }

    bool pause_on_connection_timeout() override
    {
        // Never pause: the ladder above us decides what happens after a
        // timeout, and a paused session would look connected while carrying
        // nothing.
        return false;
    }

    void acc_event(const ClientAPI::AppCustomControlMessageEvent &) override
    {
        // App-custom control messages are an OpenVPN Connect feature; a VPN
        // Gate relay never sends one and we would not act on it if it did.
    }

    void external_pki_cert_request(ClientAPI::ExternalPKICertRequest &req) override
    {
        req.error = true;
        req.errorText = "external PKI not supported";
    }

    void external_pki_sign_request(ClientAPI::ExternalPKISignRequest &req) override
    {
        req.error = true;
        req.errorText = "external PKI not supported";
    }

    // MARK: - Packet path

    /// Apple's utun devices frame every packet with a 4-byte address family in
    /// network order, and OpenVPN 3 treats the descriptor we hand it as a utun.
    /// NEPacketTunnelProvider does not use that framing — it deals in bare IP
    /// packets plus a separate protocol number — so the header is added here on
    /// the way in and stripped on the way out. Without this the far side reads
    /// our IP header four bytes late and drops everything.
    static constexpr size_t kUtunHeader = 4;

    void send_packet(const uint8_t *data, size_t len)
    {
        const int fd = our_fd_.load();
        if (fd < 0 || len == 0) return;

        const uint32_t family = htonl((data[0] >> 4) == 6
                                          ? static_cast<uint32_t>(AF_INET6)
                                          : static_cast<uint32_t>(AF_INET));

        std::vector<uint8_t> framed(kUtunHeader + len);
        std::memcpy(framed.data(), &family, kUtunHeader);
        std::memcpy(framed.data() + kUtunHeader, data, len);

        const ssize_t written = ::write(fd, framed.data(), framed.size());
        if (written > 0) tx_.fetch_add(static_cast<uint64_t>(len));
    }

    void stats(uint64_t *tx, uint64_t *rx) const
    {
        if (tx) *tx = tx_.load();
        if (rx) *rx = rx_.load();
    }

    void shutdown_pump()
    {
        if (!pump_running_.exchange(false)) return;
        const int fd = our_fd_.exchange(-1);
        // Closing our end wakes the blocking read so the thread can exit.
        if (fd >= 0) ::close(fd);
        if (pump_.joinable()) pump_.join();
    }

  private:
    void log_line(const std::string &text)
    {
        if (log_cb_) log_cb_(ctx_, text.c_str());
    }

    void pump()
    {
        // Big enough for a jumbo-ish MTU plus slack; a datagram longer than
        // this would be truncated, and OpenVPN never pushes one.
        std::vector<uint8_t> buf(65536);
        while (pump_running_.load())
        {
            const int fd = our_fd_.load();
            if (fd < 0) break;
            const ssize_t n = ::read(fd, buf.data(), buf.size());
            if (n > static_cast<ssize_t>(kUtunHeader))
            {
                uint32_t family = 0;
                std::memcpy(&family, buf.data(), kUtunHeader);
                family = ntohl(family);

                const uint8_t *payload = buf.data() + kUtunHeader;
                const size_t payload_len = static_cast<size_t>(n) - kUtunHeader;
                rx_.fetch_add(static_cast<uint64_t>(payload_len));
                if (packet_cb_)
                    packet_cb_(ctx_, payload, payload_len, static_cast<int32_t>(family));
            }
            else if (n > 0)
            {
                continue;                    // runt, nothing to forward
            }
            else if (n == 0)
            {
                break;                       // peer closed
            }
            else if (errno != EINTR)
            {
                break;                       // fd closed under us, or a real error
            }
        }
    }

    sweep_ovpn_packet_cb packet_cb_ = nullptr;
    sweep_ovpn_event_cb event_cb_ = nullptr;
    sweep_ovpn_tun_cb tun_cb_ = nullptr;
    sweep_ovpn_log_cb log_cb_ = nullptr;
    void *ctx_ = nullptr;

    mutable std::mutex settings_mutex_;
    TunSettings settings_;

    std::atomic<int> our_fd_{-1};
    std::atomic<bool> pump_running_{false};
    std::thread pump_;

    std::atomic<uint64_t> tx_{0};
    std::atomic<uint64_t> rx_{0};
};

} // namespace

struct SweepOvpnClient
{
    std::unique_ptr<SweepClient> client;
    std::thread runner;
    std::atomic<bool> running{false};
};

void sweep_ovpn_init_process(void)
{
    // Current openvpn3 initialises its process-wide state lazily inside the
    // client, so there is nothing to do here. Kept as a stable entry point so
    // callers do not have to change if that stops being true.
}

SweepOvpnClient *sweep_ovpn_new(const char *profile,
                                sweep_ovpn_packet_cb packet_cb,
                                sweep_ovpn_event_cb event_cb,
                                sweep_ovpn_tun_cb tun_cb,
                                sweep_ovpn_log_cb log_cb,
                                void *ctx)
{
    if (!profile) return nullptr;
    sweep_ovpn_init_process();

    auto handle = std::make_unique<SweepOvpnClient>();
    handle->client = std::make_unique<SweepClient>(packet_cb, event_cb, tun_cb, log_cb, ctx);

    ClientAPI::Config config;
    config.content = profile;
    config.connTimeout = 30;
    // VPN Gate relays hand out AES-128-CBC/SHA1. Refusing it outright would
    // mean the rung could never connect to the list it exists for, so the
    // weakness is surfaced in the UI instead of pretended away here.
    config.sslDebugLevel = 0;
    config.tunPersist = false;
    config.autologinSessions = true;
    config.retryOnAuthFailed = false;

    const ClientAPI::EvalConfig eval = handle->client->eval_config(config);
    if (eval.error)
    {
        if (event_cb) event_cb(ctx, "CONFIG_ERROR", eval.message.c_str());
        return nullptr;
    }

    // VPN Gate's published credential. Some relays carry no auth-user-pass in
    // their profile yet still demand a login and answer AUTH_FAILED without one
    // — 219.100.37.128 is one such. This is the documented public value from
    // vpngate.net, identical for every user; it authenticates nobody and is not
    // a secret, it is just the handshake those relays insist on.
    ClientAPI::ProvideCreds creds;
    creds.username = "vpn";
    creds.password = "vpn";
    handle->client->provide_creds(creds);

    return handle.release();
}

int sweep_ovpn_start(SweepOvpnClient *handle)
{
    if (!handle || !handle->client) return -1;
    if (handle->running.exchange(true)) return -1;   // already started

    handle->runner = std::thread([handle] {
        // connect() blocks for the life of the session and reports everything
        // through the event callback.
        const ClientAPI::Status status = handle->client->connect();
        if (status.error)
        {
            // A failure here is terminal for this session; the adapter walks
            // the ladder on it rather than retrying in place.
            ClientAPI::Event ev;
            ev.error = true;
            ev.fatal = true;
            ev.name = "CONNECT_FAILED";
            ev.info = status.message.empty() ? status.status : status.message;
            handle->client->event(ev);
        }
        handle->running.store(false);
    });
    return 0;
}

void sweep_ovpn_send(SweepOvpnClient *handle, const uint8_t *data, size_t len)
{
    if (!handle || !handle->client) return;
    handle->client->send_packet(data, len);
}

void sweep_ovpn_stop(SweepOvpnClient *handle)
{
    if (!handle || !handle->client) return;
    handle->client->stop();
}

void sweep_ovpn_reconnect(SweepOvpnClient *handle)
{
    if (!handle || !handle->client) return;
    handle->client->reconnect(0);
}

void sweep_ovpn_stats(SweepOvpnClient *handle, uint64_t *tx, uint64_t *rx)
{
    if (!handle || !handle->client)
    {
        if (tx) *tx = 0;
        if (rx) *rx = 0;
        return;
    }
    handle->client->stats(tx, rx);
}

void sweep_ovpn_free(SweepOvpnClient *handle)
{
    if (!handle) return;
    if (handle->client)
    {
        handle->client->stop();
        handle->client->shutdown_pump();
    }
    if (handle->runner.joinable()) handle->runner.join();
    delete handle;
}
