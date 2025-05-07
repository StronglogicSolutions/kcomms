#pragma once

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <memory>
#include <string>
#include "database.hpp"

using boost::asio::ip::tcp;
using json = nlohmann::json;

class client_session : public std::enable_shared_from_this<client_session> {
public:
  client_session(tcp::socket socket, database& db);
  void start();

private:
  void do_read();
  void handle_message(const json& message);
  void send_message(const json& message);

  tcp::socket socket_;
  database& db_;
  boost::asio::streambuf buffer_;
  std::string username_;
};

class server {
public:
  server(boost::asio::io_context& io_context, short port);
private:
  void do_accept();
  tcp::acceptor acceptor_;
  database db_;
};
