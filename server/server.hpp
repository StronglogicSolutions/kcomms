#pragma once

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include "database.hpp"
#include "logger.hpp"

using namespace kiq::log;
using boost::asio::ip::tcp;
using json = nlohmann::json;


class server {
public:
  server(boost::asio::io_context& io_context, short port);
  void store_message(const std::string& recipient, const json& message);
  std::vector<json> get_pending_messages(const std::string& username);

private:
  void do_accept();

  tcp::acceptor acceptor_;
  database db_;
  std::map<std::string, std::vector<json>> message_queues_;
};

class client_session : public std::enable_shared_from_this<client_session> {
public:
  client_session(tcp::socket socket, database& db, server *ptr);
  void start();

private:
  void do_read();
  void handle_message(const json& message);
  void send_message(const json& message);

  tcp::socket socket_;
  database& db_;
  boost::asio::streambuf buffer_;
  std::string username_;
  server *server_ptr_;
};

