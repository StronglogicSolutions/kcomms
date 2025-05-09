#include "server.hpp"
#include <iostream>

client_session::client_session(tcp::socket socket, database& db, server *ptr)
  : socket_(std::move(socket)), db_(db),
    server_ptr_(ptr)
{
}

void client_session::start()
{
  do_read();
}

void client_session::do_read()
{
  auto self(shared_from_this());
  boost::asio::async_read_until(socket_, buffer_, '\n',
    [this, self](boost::system::error_code ec, std::size_t) {
      if (!ec) {
        std::istream is(&buffer_);
        std::string message;
        std::getline(is, message);
        try {
          json parsed_message = json::parse(message);
          handle_message(parsed_message);
        } catch (const json::exception& e) {
          json error = {{"type", "error"}, {"message", "Invalid JSON"}};
          send_message(error);
        }
        do_read();
      }
    });
}

void client_session::handle_message(const json& message)
{
//  std::cout << "Handling message:\n" << message.dump() << std::endl;
std::string type = message.value("type", "");
  if (type == "register") {
    std::string username = message.value("username", "");
    user_key_bundle bundle;
    bundle.identity_key = message.value("identity_key", "");
    bundle.signed_pre_key = message.value("signed_pre_key", "");
    for (const auto& pre_key : message["one_time_pre_keys"]) {
      bundle.one_time_pre_keys.push_back(pre_key.get<std::string>());
    }
    if (db_.register_user(username, bundle)) {
      username_ = username;
      send_message({{"type", "register_response"}, {"status", "success"}});
    } else {
      send_message({{"type", "register_response"}, {"status", "failure"}});
    }
  } else if (type == "get_key_bundle") {
    std::string target_username = message.value("target_username", "");
    auto bundle = db_.get_user_key_bundle(target_username);
    json response = {
      {"type", "key_bundle_response"},
      {"username", target_username},
      {"identity_key", bundle.identity_key},
      {"signed_pre_key", bundle.signed_pre_key},
      {"one_time_pre_keys", bundle.one_time_pre_keys}
    };
    send_message(response);
  } else if (type == "send_message") {
    std::string recipient = message.value("recipient", "");
    std::string sender = message.value("sender", "");
    std::string content = message.value("content", "");
    if (recipient.find("group:") == 0) {
      auto members = db_.get_group_members(recipient);
      std::cout << "Routing message from " << sender << " to group " << recipient
                << " with " << members.size() << " members" << std::endl;
      for (const auto& member : members) {
        if (member != sender) {
          std::cout << "Storing message for " << member << std::endl;
          server_ptr_->store_message(member, message);
        }
      }
      std::cout << "[" << sender << " to " << recipient << "]: " << content << std::endl;
    } else {
      server_ptr_->store_message(recipient, message);
    }
    send_message({{"type", "send_message_response"}, {"status", "success"}});
  } else if (type == "get_messages") {
    auto messages = server_ptr_->get_pending_messages(username_);

    if (messages.empty())
      return;

    std::cout << "Sending " << messages.size() << " messages to " << username_ << std::endl;
    json response = {{"type", "messages_response"}, {"messages", messages}};
    send_message(response);
  } else if (type == "create_group") {
    std::string group_id = message.value("group_id", "");
    std::string group_name = message.value("group_name", "");
    if (db_.create_group(group_id, group_name) && db_.add_user_to_group(group_id, username_)) {
      send_message({{"type", "create_group_response"}, {"status", "success"}});
    } else {
      send_message({{"type", "create_group_response"}, {"status", "failure"}});
    }
  } else if (type == "join_group") {
    std::string group_id = message.value("group_id", "");
    if (db_.add_user_to_group(group_id, username_)) {
      send_message({{"type", "join_group_response"}, {"status", "success"}});
    } else {
      send_message({{"type", "join_group_response"}, {"status", "failure"}});
    }
  }
}

void client_session::send_message(const json& message)
{
  auto self(shared_from_this());
  std::string message_str = message.dump() + "\n";
  boost::asio::async_write(socket_, boost::asio::buffer(message_str),
    [self](boost::system::error_code ec, std::size_t) {
      if (ec) {
        std::cerr << "Error sending message: " << ec.message() << std::endl;
      }
    });
}

server::server(boost::asio::io_context& io_context, short port)
  : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
    db_("signal_server.db")
{
  do_accept();
}

void server::do_accept()
{
  acceptor_.async_accept(
    [this](boost::system::error_code ec, tcp::socket socket) {
      if (!ec) {
        std::make_shared<client_session>(std::move(socket), db_, this)->start();
      }
      do_accept();
    });
}

void server::store_message(const std::string& recipient, const json& message)
{
  message_queues_[recipient].push_back(message);
}

std::vector<json> server::get_pending_messages(const std::string& username)
{
  auto it = message_queues_.find(username);
  if (it == message_queues_.end()) {
    return {};
  }
  std::vector<json> messages = std::move(it->second);
  message_queues_.erase(it);
  return messages;
}

