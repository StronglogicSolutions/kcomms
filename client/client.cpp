#include "client.hpp"
#include <iostream>
#include <stdexcept>
#include <openssl/rand.h>

client::client(boost::asio::io_context& io_context, const std::string& host, const std::string& port,
               const std::string& username, const std::string& db_path)
  : io_context_(io_context),
    socket_(io_context),
    storage_(db_path),
    username_(username),
    signal_context_(nullptr),
    store_context_(nullptr),
    cli_(*this, username),
    poll_timer_(io_context)
{
  initialize_signal();
  tcp::resolver resolver(io_context_);
  auto endpoints = resolver.resolve(host, port);
  boost::asio::async_connect(socket_, endpoints,
    [this](boost::system::error_code ec, const tcp::endpoint&) {
      if (!ec) {
        do_connect();
        create_group("group:default", "DefaultChat");
        join_group("group:default");
      } else {
        std::cerr << "Connect failed: " << ec.message() << std::endl;
      }
    });
}

client::~client()
{
  if (store_context_) {
    signal_protocol_store_context_destroy(store_context_);
  }
  if (signal_context_) {
    signal_context_destroy(signal_context_);
  }
}

void client::start()
{
  cli_.start();
  start_poll();
  do_read();
}

void client::start_poll()
{
  do_poll();
}

void client::do_poll()
{
  json get_messages = {{"type", "get_messages"}};
  do_write(get_messages);

  poll_timer_.expires_after(std::chrono::seconds(1));
  poll_timer_.async_wait([this](boost::system::error_code ec) {
    if (!ec) {
      do_poll();
    }
    else {
    std::cerr << "Poll error: " << ec.message() << std::endl;
    }
  });
}

void client::log_function(int level, const char* message, size_t length, void* user_data)
{
  std::cerr << "[Level " << level << "] " << std::string(message, length) << std::endl;
}

void client::initialize_signal()
{
  signal_context_create(&signal_context_, nullptr);
  signal_context_set_log_function(signal_context_, log_function);

  signal_crypto_provider crypto_provider = {
    .random_func = [](uint8_t* data, size_t len, void*) -> int {
      return RAND_bytes(data, len) == 1 ? SG_SUCCESS : SG_ERR_UNKNOWN;
    },
    .hmac_sha256_init_func = nullptr,  // TODO: Implement using OpenSSL
    .hmac_sha256_update_func = nullptr,
    .hmac_sha256_final_func = nullptr,
    .hmac_sha256_cleanup_func = nullptr,
//    .aes_gcm_encrypt_func = nullptr,
 //   .aes_gcm_decrypt_func = nullptr,
    .user_data = nullptr
  };
  signal_context_set_crypto_provider(signal_context_, &crypto_provider);

  signal_protocol_store_context_create(&store_context_, signal_context_);
  storage_.initialize_signal(store_context_);

  // Generate keys (simplified placeholder)
  // TODO: Use signal_protocol_key_helper_generate_identity_key_pair, etc.
}

void client::do_connect()
{
  auto key_bundle = storage_.generate_key_bundle();
  json register_message = {
    {"type", "register"},
    {"username", username_},
    {"identity_key", key_bundle.identity_key},
    {"signed_pre_key", key_bundle.signed_pre_key},
    {"one_time_pre_keys", key_bundle.one_time_pre_keys}
  };
  do_write(register_message);
}

void client::do_read()
{
  boost::asio::async_read_until(socket_, buffer_, '\n',
    [this](boost::system::error_code ec, std::size_t) {
      if (!ec) {
        std::istream is(&buffer_);
        std::string message;
        std::getline(is, message);
        try {
          json parsed_message = json::parse(message);
          handle_server_message(parsed_message);
        } catch (const json::exception& e) {
          std::cerr << "Invalid JSON: " << e.what() << std::endl;
        }
        do_read();
      } else {
        std::cerr << "Read error: " << ec.message() << std::endl;
      }
    });
}

void client::do_write(const json& message)
{
  std::string message_str = message.dump() + "\n";
  boost::asio::async_write(socket_, boost::asio::buffer(message_str),
    [this](boost::system::error_code ec, std::size_t) {
      if (ec) {
        std::cerr << "Write error: " << ec.message() << std::endl;
      }
    });
}

void client::handle_server_message(const json& message)
{
//  std::cout << "Server message:\n" << message.dump() << std::endl;
  std::string type = message.value("type", "");
  if (type == "register_response") {
    if (message.value("status", "") == "success") {
      std::cout << "Registered successfully as " << username_ << std::endl;
    } else {
      std::cerr << "Registration failed. Status: " << message.value("status", "") << std::endl;
    }
  } else if (type == "messages_response") {
    for (const auto& msg : message["messages"]) {
      std::string sender = msg.value("sender", "");
      std::string ciphertext = msg.value("content", "");
      std::string plaintext = decrypt_message(sender, ciphertext);
      std::cout << sender << ": " << plaintext << std::endl;
    }
  } else if (type == "create_group_response" || type == "join_group_response") {
    std::string status = message.value("status", "");
    std::cout << type << ": " << status << std::endl;
  }
}

void client::send_message(const std::string& recipient, const std::string& message)
{
  std::string ciphertext = encrypt_message(recipient, message);
  json message_json = {
    {"type", "send_message"},
    {"recipient", recipient},
    {"sender", username_},
    {"content", ciphertext}
  };
  do_write(message_json);
}

void client::create_group(const std::string& group_id, const std::string& group_name)
{
  json message = {
    {"type", "create_group"},
    {"group_id", group_id},
    {"group_name", group_name}
  };
  do_write(message);
  storage_.save_group(group_id, group_name);
}

void client::join_group(const std::string& group_id)
{
  json message = {{"type", "join_group"}, {"group_id", group_id}};
  do_write(message);
}

std::string client::encrypt_message(const std::string& recipient, const std::string& message)
{
  // Placeholder: Implement Signal Protocol encryption
  // Fetch key bundle, create session, encrypt message
  return message;
}

std::string client::decrypt_message(const std::string& sender, const std::string& ciphertext)
{
  // Placeholder: Implement Signal Protocol decryption
  // Load session, decrypt message
  return ciphertext;
}
