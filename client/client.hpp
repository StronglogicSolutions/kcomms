#pragma once

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include <string>
#include <vector>
#include "cli.hpp"
#include <sodium.h>

struct user_key_bundle {
  std::string key;
};

struct encrypt_struct_t {
  std::string cipher_text;
  std::string nonce;
};

using boost::asio::ip::tcp;
using json = nlohmann::json;

extern std::string base64_encode(const uint8_t* data, size_t len);
extern std::vector<uint8_t> base64_decode(const std::string& input);

class client : public std::enable_shared_from_this<client> {
public:
  client (boost::asio::io_context& io_context, const std::string& host, const std::string& port,
          const std::string& username, const std::string& db_path);

  void start();
  void send_message(const std::string& recipient, const std::string& message);
  void create_group(const std::string& group_id, const std::string& group_name);
  void join_group  (const std::string& group_id);

private:
  static void log_function(int level, const char* message, size_t length, void* user_data);

  void        init();
  void        do_connect();
  void        do_read();
  void        start_poll();
  void        do_poll();
  void        do_write(json message);
  void        handle_server_message(const json& message);
  encrypt_struct_t encrypt_message(const std::string& recipient, int device_id, const std::string& message);
  std::string decrypt_message(const std::string& sender, int device_id, const encrypt_struct_t& encrypted);
  void        start_session(const std::string& recipient_id, int device_id, const user_key_bundle& bundle);
  user_key_bundle fetch_key_bundle(const std::string& recipient_id);

  using user_bundles_t = std::map<std::string, user_key_bundle>;

  boost::asio::io_context&       io_context_;
  tcp::socket                    socket_;
  std::string                    host_;
  std::string                    port_;
  std::string                    username_;
  boost::asio::streambuf         buffer_;
  unsigned char                  key_[crypto_secretbox_KEYBYTES];
  cli                            cli_;
  boost::asio::steady_timer      poll_timer_;
  user_key_bundle                key_bundle_;
  user_bundles_t                 user_bundles_;
  std::vector<std::string>       received_;
};
