#include "server.hpp"
#include "database.hpp"
#include <fmt/format.h>
#include <string>
//----------------------------------------------------------------
client_session::client_session(tcp::socket socket, database& db, server *ptr)
  : socket_(std::move(socket)), db_(db),
    server_ptr_(ptr)
{
  klog().d("Initialized client session");
  run_queue_ = true;
  worker_ = std::async(std::launch::async, [this] { handle_queue(); });
}
//----------------------------------------------------------------
client_session::~client_session()
{
  run_queue_ = false;
  if (worker_.valid())
    worker_.wait();
}
//----------------------------------------------------------------
void client_session::start()
{
  klog().d("Client session starting");
  do_read();
}
//----------------------------------------------------------------
void client_session::handle_queue()
{
  while (run_queue_)
  {
    if (queue_.empty())
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      continue;
    }

    auto msg = std::move(queue_.front());
    queue_.pop_front();
    handle_message(std::move(msg));
  }

}
//----------------------------------------------------------------
void client_session::do_read()
{
  auto self(shared_from_this());
  boost::asio::async_read_until(socket_, read_buffer_, '\n',
    [this, self](boost::system::error_code ec, std::size_t)
    {
      if (!ec)
      {
        std::istream is(&read_buffer_);
        std::string message;
        std::getline(is, message);
        try
        {
          if (json::accept(message))
          {
            json parsed_message = json::parse(message);
            queue_.push_back(parsed_message);
          }
        }
        catch (const json::exception& e)
        {
          klog().e("Failed to parse JSON: {}", e.what());
          json error = {{"type", "error"}, {"message", "Invalid JSON"}};
          send_message(error);
        }
        do_read();
      }
      else
        klog().e("We had an error: {}", ec.message());
    });
}
//----------------------------------------------------------------
json bundle_to_json(const user_key_bundle& bundle, const std::string& name)
{
  json j{
    {"type", "key_bundle_response"},
    {"username", name},
    {"key", bundle.key}
  };

  return j;
}
//----------------------------------------------------------------
void client_session::handle_message(json&& data)
{
  const auto message = std::move(data);
  auto get_user_bundle = [this](const auto name) -> json
  {
    return bundle_to_json(db_.get_user_key_bundle(name), name);
  };

  try
  {
//    klog().t("Handling message:\n{}", message.dump());
    const auto type = message.value("type", "");
    if (type == "register")
    {
      const auto      username = message.value("username", "");
      user_key_bundle bundle;
      bundle.key = message.value("key", "");

      if (db_.register_user(username, bundle))
      {
        username_ = username;
        send_message({{"type", "register_response"}, {"status", "success"}});
      } else {
        send_message({{"type", "register_response"}, {"status", "failure"}});
      }
    }
    else if (type == "get_key_bundle")
      send_message(get_user_bundle(message.value("target_username", "")));
    else if (type == "send_message")
    {
      const auto recipient = message.value("recipient", "");
      const auto sender    = message.value("sender", "");
      const auto content   = message.value("content", "");
      const auto nonce     = message.value("nonce", "");
      if (recipient.find("group:") == 0)
      {
        for (const auto& member : db_.get_group_members(recipient))
          if (member != username_)
            server_ptr_->store_message(member, message);
      }
      else
      {
        klog().t("{} sent a message for {}", username_, recipient);
        server_ptr_->store_message(recipient, message);
      }
      send_message({{"type", "send_message_response"}, {"status", "success"}});
    }
    else if (type == "get_messages")
    {
      const auto messages = server_ptr_->get_pending_messages(username_);

      if (messages.empty())
        return;

      klog().i("Sending {} messages to {}", messages.size(), username_);
      const json response = {{"type", "messages_response"}, {"messages", messages}};
      send_message(response);
    }
    else if (type == "create_group")
    {
      const auto group_id   = message.value("group_id", "");
      const auto group_name = message.value("group_name", "");
      if (db_.create_group(group_id, group_name) && db_.add_user_to_group(group_id, username_))
        send_message({{"type", "create_group_response"}, {"status", "success"}});
      else
        send_message({{"type", "create_group_response"}, {"status", "failure"}});

    }
    else if (type == "join_group")
    {
      const auto group_id = message.value("group_id", "");
      if (db_.add_user_to_group(group_id, username_))
      {
        send_message({{"type", "join_group_response"}, {"status", "success"}});
        for (const auto& member : db_.get_group_members("group:default"))
          send_message(get_user_bundle(member));
        server_ptr_->on_member_join(username_, this, get_user_bundle(username_));
      }
      else
      {
        klog().e("{} failed to join group", username_);
        send_message({{"type", "join_group_response"}, {"status", "failure"}});
      }
    }
  }
  catch (const json::exception& e)
  {
    klog().e("Failed to handle message. Failed to parse JSON: {}", e.what());
  }
}
//----------------------------------------------------------------
void client_session::send_message(const json& message)
{
  auto self(shared_from_this());
  const auto message_str = message.dump() + "\n";
  boost::asio::async_write(socket_, boost::asio::buffer(message_str),
    [this, self](boost::system::error_code ec, std::size_t)
    {
      if (ec)
        klog().e("Error sending message: {}", ec.message());
    });
}
//----------------------------------------------------------------
server::server(boost::asio::io_context& io_context, short port)
: acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
  db_("signal_server.db")
{
  klog().i("Server starting chat on {}", port);
  do_accept();
}
//----------------------------------------------------------------
void server::do_accept()
{
  acceptor_.async_accept(
    [this](boost::system::error_code ec, tcp::socket socket)
    {
      if (!ec)
      {
        const auto temp_id = std::to_string(clients_.size());
        auto client = std::make_shared<client_session>(std::move(socket), db_, this);
        client->start();
        clients_.insert_or_assign(temp_id,  client);
      }
      do_accept();
    });
}
//----------------------------------------------------------------
void server::store_message(const std::string& recipient, const json& message)
{
  message_queues_[recipient].push_back(message);
}
//----------------------------------------------------------------
std::vector<json> server::get_pending_messages(const std::string& username)
{
  auto it = message_queues_.find(username);
  if (it == message_queues_.end())
    return {};

  std::vector<json> messages = std::move(it->second);
  message_queues_.erase(it);
  return messages;
}
//----------------------------------------------------------------
void server::on_member_join(const std::string& new_name, client_session *client, const json& message)
{
  std::string old_key;

  for (const auto& [name, client_session_ptr] : clients_)
  {
    if (client_session_ptr.get() == client)
      old_key = name;
    else if (name != new_name)
      client_session_ptr->send_message(message);
  }

  if (!old_key.empty())
  {
    if (auto it = clients_.find(old_key); it != clients_.end())
    {
      auto ptr = std::move(it->second);
      clients_.erase(it);
      clients_.emplace(new_name, std::move(ptr));
    }
  }
}

