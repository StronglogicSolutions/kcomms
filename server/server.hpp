#pragma once

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include "database.hpp"
#include "logger.hpp"
#include <future>
#include <deque>

using namespace kiq::log;
using boost::asio::ip::tcp;
using json = nlohmann::json;

class server;

class client_session : public std::enable_shared_from_this<client_session> {
public:
  client_session(tcp::socket socket, database& db, server *ptr);
//  client_session(client_session&& c) noexcept
//  : socket_(std::move(c.socket_)),
//        db_(c.db_),
//        username_(c.username_),
//        server_ptr_(c.server_ptr_)
//  {}

  ~client_session();

//  client_session& operator=(client_session&& c) noexcept
//  {
//    if (this != &c)
//    {
//      socket_     = std::move(c.socket_);
//      db_         = std::move(c.db_);
//      username_   = c.username_;
//      server_ptr_ = c.server_ptr_;
//    }
//    return *this;
//  }
//
//  client_session(const client_session&)            = delete;
//  client_session& operator=(const client_session&) = delete;

  void start();
  void send_message(const json& message);

private:
  void do_read();
  void handle_message(json&& message);
  void handle_queue();

  using recvd_msgs_t = std::vector<json>;
  using queue_t      = std::deque<json>;

  tcp::socket socket_;
  database& db_;
  std::string username_;
  boost::asio::streambuf read_buffer_;
  server *server_ptr_;
  queue_t      queue_;
  bool         run_queue_{false};
  std::future<void> worker_;
};

class server {
public:
  server(boost::asio::io_context& io_context, short port);
  void store_message(const std::string& recipient, const json& message);
  std::vector<json> get_pending_messages(const std::string& username);
  void on_member_join(const std::string& name, client_session *client, const json& message);
  std::vector<std::string> get_names() const;

private:
  void do_accept();

  void handle_register(const std::string& username, const std::string& body, std::string& response);
  void handle_get_key_bundle(const std::string& recipient_id, std::string& response);
  using client_ptr_t = std::shared_ptr<client_session>;
  using client_map_t = std::map<std::string, client_ptr_t>;
  tcp::acceptor acceptor_;

  database db_;
  std::map<std::string, std::vector<json>> message_queues_;
  client_map_t  clients_;
};

