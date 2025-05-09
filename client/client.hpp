#pragma once

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <signal_protocol.h>
#include <memory>
#include <string>
#include "storage.hpp"
#include "cli.hpp"

using boost::asio::ip::tcp;
using json = nlohmann::json;

class client : public std::enable_shared_from_this<client> {
public:
  client(boost::asio::io_context& io_context, const std::string& host, const std::string& port,
         const std::string& username, const std::string& db_path);
  ~client();
  void start();
  void send_message(const std::string& recipient, const std::string& message);
  void create_group(const std::string& group_id, const std::string& group_name);
  void join_group(const std::string& group_id);

private:
  static void log_function(int level, const char* message, size_t length, void* user_data);
  void initialize_signal();
  void do_connect();
  void do_read();
  void start_poll();
  void do_poll();
  void do_write(const json& message);
  void handle_server_message(const json& message);
  std::string encrypt_message(const std::string& recipient, const std::string& message);
  std::string decrypt_message(const std::string& sender, const std::string& ciphertext);

  boost::asio::io_context& io_context_;
  tcp::socket socket_;
  storage storage_;
  std::string username_;
  boost::asio::streambuf buffer_;
  signal_context* signal_context_;
  signal_protocol_store_context* store_context_;
  cli             cli_;
  boost::asio::steady_timer poll_timer_;
};
