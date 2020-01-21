extern "C"
{
#include "wpa_auth_multi.h"
}

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <thread>
#include <vector>

extern "C"
{
    // clang-format off
#include "utils/includes.h"
#include "utils/common.h"
#include "common/defs.h"
#include "common/wpa_common.h"
#include "common/eapol_common.h"
    // clang-format on
}

namespace
{

using namespace std::literals::chrono_literals;

constexpr size_t blocks_cnt = 14;
constexpr size_t lines_cnt = 256;

constexpr uint32_t mode_A_id = 0;

struct Sync
{
    Sync(std::ostream& target) : target{target}
    {
    }
    ~Sync()
    {
        target << oss.str() << std::flush;
    }

    template <typename T> Sync& operator<<(T&& val)
    {
        oss << std::forward<T>(val);
        return *this;
    }

    Sync& operator<<(std::ostream& (*f)(std::ostream&))
    {
        f(oss);
        return *this;
    }

    std::ostringstream oss;
    std::ostream& target;
};

struct block
{
    block() = default;
    block(block&& b) : lines{std::move(b.lines)}, id{b.id}, busy{b.busy.load()}
    {
    }

    std::vector<multi_psk_line_t> lines;
    uint32_t id;
    std::atomic<bool> busy;
};

block block_A;
std::vector<block> blocks_B;
std::vector<std::thread> workers;

struct user_info
{
    std::vector<uint8_t> data;
    size_t data_len;
    std::vector<uint8_t> mic;
    size_t mic_len;
    const uint8_t* ANonce;
    const uint8_t* SNonce;
    const uint8_t* AA;
    const uint8_t* SPA;
    int akmp;
    int cipher;
};

uint32_t global_serial{0};
user_info current_req;
std::shared_mutex mtxWorkers;
std::condition_variable_any cvWorkers;
std::atomic<multi_psk_line_t*> check_result;
std::atomic<int> busy;
std::mutex mtxWait;
std::condition_variable cvWait;

uint8_t* get_mic(const uint8_t* data)
{
    const auto hdr = (struct ieee802_1x_hdr*)data;
    const auto key = (struct wpa_eapol_key*)(hdr + 1);
    const auto mic_pos = (uint8_t*)(key + 1);
    return mic_pos;
}

uint16_t get_key_info(const uint8_t* data)
{
    const auto hdr = (struct ieee802_1x_hdr*)data;
    const auto key = (struct wpa_eapol_key*)(hdr + 1);
    const auto key_info = WPA_GET_BE16(key->key_info);
    return key_info;
}

bool check_req(const user_info& info, const multi_psk_line_t& line)
{
    const auto key_info = get_key_info(info.data.data());
    wpa_ptk ptk{};
    wpa_pmk_to_ptk(line.pmk, 32, "Pairwise key expansion", info.AA, info.SPA,
                   info.ANonce, info.SNonce, &ptk, info.akmp, info.cipher,
                   nullptr, 0);
    std::array<uint8_t, WPA_EAPOL_KEY_MIC_MAX_LEN> mic{};
    const size_t mic_len = current_req.mic_len;

    if (wpa_eapol_key_mic(ptk.kck, ptk.kck_len, info.akmp,
                          key_info & WPA_KEY_INFO_TYPE_MASK, info.data.data(),
                          info.data_len, mic.data()))
        return false;

    return std::equal(mic.data(), mic.data() + mic_len, current_req.mic.data());
}

void worker_thread(block& blk)
{
    uint32_t serial{0};
    Sync(std::cout) << "Thread " << blk.id << " starts." << std::endl;
    while (blk.busy.load(std::memory_order_seq_cst))
    {
        std::shared_lock lock{mtxWorkers};
        if (cvWorkers.wait_for(lock, 1s,
                               [&serial] { return global_serial != serial; }))
        {
            auto now = std::chrono::system_clock::now().time_since_epoch();
            auto now_hour = std::chrono::duration_cast<std::chrono::hours>(now);
            auto now_time = now_hour.count();

            for (auto& ln : blk.lines)
            {
                if (check_result.load()) break;
                if (!ln.is_valid || ln.time <= now_time) continue;
                if (check_req(current_req, ln))
                {
                    check_result.store(&ln, std::memory_order_seq_cst);
                    break;
                }
            }

            --busy;

            serial = global_serial;
        }
        cvWait.notify_one();
    }
    Sync(std::cout) << "Thread " << blk.id << " quits." << std::endl;
}

} // namespace

void multi_psk_init(const uint8_t* pre_psk, size_t pre_psk_len,
                    const uint8_t* ssid, size_t ssid_len)
{
    block_A.lines.resize(lines_cnt);
    block_A.id = mode_A_id;
    block_A.busy.store(true, std::memory_order_seq_cst);
    multi_psk_fill_block(block_A.lines.data(), block_A.lines.size(), block_A.id,
                         pre_psk, pre_psk_len, ssid, ssid_len);

    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto now_hour = std::chrono::duration_cast<std::chrono::hours>(now);
    uint32_t block_id = now_hour.count() / 24;

    blocks_B.resize(blocks_cnt);
    std::vector<std::thread> thds;
    thds.reserve(blocks_cnt);
    std::cout << "Multi PSK: Filling blocks " << std::flush;
    for (auto& blk : blocks_B)
        thds.emplace_back([&] {
            blk.lines.resize(lines_cnt);
            blk.id = block_id++;
            blk.busy.store(true, std::memory_order_seq_cst);
            multi_psk_fill_block(blk.lines.data(), blk.lines.size(), blk.id,
                                 pre_psk, pre_psk_len, ssid, ssid_len);
            std::cout << '.' << std::flush;
        });
    for (auto& t : thds)
        t.join();
    std::cout << " done" << std::endl;

    check_result.store(nullptr, std::memory_order_seq_cst);
    busy.store(0, std::memory_order_seq_cst);

    workers.emplace_back(worker_thread, std::ref(block_A));
    for (auto& blk : blocks_B)
        workers.emplace_back(worker_thread, std::ref(blk));
}

void multi_psk_visit_block(multi_psk_visit_block_handler handler, void* data)
{
    bool cont = handler(0, block_A.lines.data(), block_A.lines.size(), data);
    for (auto& blk : blocks_B)
    {
        if (!cont) break;
        cont = handler(blk.id, blk.lines.data(), blk.lines.size(), data);
    }
}

multi_psk_line_t* multi_psk_enum(const uint8_t* data, size_t data_len,
                                 const uint8_t ANonce[128],
                                 const uint8_t SNonce[128], const uint8_t AA[6],
                                 const uint8_t SPA[6], int akmp, int cipher)
{
    std::unique_lock lock{mtxWait};
    cvWait.wait(lock, [] { return busy.load() == 0; });

    if (data_len < sizeof(ieee802_1x_hdr) + sizeof(wpa_eapol_key))
        return nullptr;

    current_req.data.resize(data_len);
    std::copy(data, data + data_len, current_req.data.data());
    current_req.mic_len = wpa_mic_len(akmp, 32);
    current_req.mic.resize(current_req.mic_len);
    const auto mic = get_mic(current_req.data.data());
    std::copy(mic, mic + current_req.mic_len, current_req.mic.data());
    std::fill_n(mic, current_req.mic_len, 0);
    current_req.data_len = data_len;
    current_req.ANonce = ANonce;
    current_req.SNonce = SNonce;
    current_req.AA = AA;
    current_req.SPA = SPA;
    current_req.akmp = akmp;
    current_req.cipher = cipher;

    check_result.store(nullptr, std::memory_order_seq_cst);
    busy.store(workers.size());
    ++global_serial;
    cvWorkers.notify_all();
    cvWait.wait(lock, [] {
        auto busy_val = busy.load();
        Sync(std::cout) << "multi_psk_enum wakes up: busy = " << busy_val
                        << std::endl;
        return busy_val == 0;
    });

    return check_result.load();
}
