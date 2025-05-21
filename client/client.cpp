#include "client.hpp"
#include <iostream>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sodium/crypto_secretbox.h>
#include <stdexcept>

client::client(boost::asio::io_context& io_context, const std::string& host, const std::string& port,
               const std::string& username, const std::string& db_path)
  : io_context_(io_context),
    socket_(io_context),
    host_(host),
    port_(port),
    username_(username),
    cli_(*this, username),
    poll_timer_(io_context)
{
  init();
  tcp::resolver resolver(io_context_);
  auto          endpoints = resolver.resolve(host, port);
  boost::asio::async_connect(socket_, endpoints,
    [this](boost::system::error_code ec, const tcp::endpoint&)
    {
      if (!ec)
      {
        do_connect();
        create_group("group:default", "DefaultChat");
        join_group  ("group:default");
      }
      else
      {
        std::cerr << "Connect failed: " << ec.message() << std::endl;
      }
    });
}
//-------------------------------------
void client::start()
{
  cli_.start();
  start_poll();
  do_read();
}
//-------------------------------------
void client::start_poll()
{
  do_poll();
}
//-------------------------------------
void client::do_poll()
{
  json get_messages = {{"type", "get_messages"}};
  do_write(get_messages);

  poll_timer_.expires_after(std::chrono::seconds(1));
  poll_timer_.async_wait([this](boost::system::error_code ec)
  {
    if (!ec)
      do_poll();
    else
      std::cerr << "Poll error: " << ec.message() << std::endl;
  });
}
//-------------------------------------
void client::log_function(int level, const char* message, size_t length, void* user_data)
{
  std::cerr << "[Level " << level << "] " << std::string(message, length) << std::endl;
}
//-------------------------------------
void client::init()
{
  // Generate a 256-bit key
  crypto_secretbox_keygen(key_);
  crypto_secretbox_keygen(key_);
}
//-------------------------------------
void client::do_connect()
{
  key_bundle_ = user_key_bundle{.key = {key_, key_ + 32}};
  user_bundles_.insert_or_assign(username_, key_bundle_);

  size_t base64_maxlen = sodium_base64_ENCODED_LEN(crypto_secretbox_KEYBYTES, sodium_base64_VARIANT_ORIGINAL);
  std::vector<char> base64_key(base64_maxlen);
  sodium_bin2base64(base64_key.data(), base64_maxlen, reinterpret_cast<const unsigned char*>(key_bundle_.key.data()), crypto_secretbox_KEYBYTES, sodium_base64_VARIANT_ORIGINAL);

  json register_message = {
    {"type", "register"},
    {"username", username_},
    {"key", base64_key.data() }
  };

  do_write(register_message);
}
//-------------------------------------
void client::do_read()
{
  boost::asio::async_read_until(socket_, buffer_, '\n',
    [this](boost::system::error_code ec, std::size_t)
    {
      if (!ec)
      {
        std::istream is(&buffer_);
        std::string message;
        std::getline(is, message);

        try
        {
          json parsed_message = json::parse(message);
          handle_server_message(parsed_message);
        }
        catch (const json::exception& e)
        {
          std::cerr << "Invalid JSON: " << e.what() << std::endl;
        }

        do_read();
      }
      else
        std::cerr << "Read error: " << ec.message() << std::endl;
    });
}
//-------------------------------------
void client::do_write(json message)
{
  received_.push_back(message.dump() + "\n");
  boost::asio::async_write(socket_, boost::asio::buffer(received_.back()),
    [this](boost::system::error_code ec, std::size_t)
    {
      if (ec)
        std::cerr << "Write error: " << ec.message() << std::endl;
    });
}
//-------------------------------------
void client::handle_server_message(const json& message)
{
//  std::cout << "server message:\n" << message.dump() << std::endl;
  std::string type = message.value("type", "");
  if (type == "register_response")
  {
    if (message.value("status", "") == "success")
      std::cout << "Registered successfully as " << username_ << std::endl;
    else
      std::cerr << "Registration failed. Status: " << message.value("status", "") << std::endl;
  }
  else if (type == "messages_response")
  {
    for (const auto& msg : message["messages"])
    {
      const std::string sender     = msg.value("sender", "");
      const std::string ciphertext = msg.value("content", "");
      const std::string nonce      = msg.value("nonce", "");
      const std::string plaintext  = decrypt_message(sender, 1, {ciphertext, nonce});
      std::cout << sender << ": " << plaintext << std::endl;
    }
  }
  else if (type == "create_group_response" || type == "join_group_response")
  {
    std::string status = message.value("status", "");
    std::cout << type << ": " << status << std::endl;
  }
  else if (type == "key_bundle_response")
  {
    const auto base64_key_str = message.value("key", "");
    unsigned char decoded_key[crypto_secretbox_KEYBYTES];
    size_t bin_len;
    if (sodium_base642bin(decoded_key, crypto_secretbox_KEYBYTES,
                          base64_key_str.c_str(), base64_key_str.size(),
                          nullptr, &bin_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
      std::cerr << "Base64 decoding of key failed. FAILD to get user key" << std::endl;
      return;
    }

    const auto user   = message.value("username", "");
    const auto bundle = user_key_bundle{.key = {decoded_key, decoded_key + crypto_secretbox_KEYBYTES }};
    if (!bundle.key.empty() && user != username_)
      user_bundles_.insert_or_assign(user, bundle);
  }
}
//-------------------------------------
void client::send_message(const std::string& recipient, const std::string& message)
{
  for (const auto& info : user_bundles_)
  {
    if (info.first == username_)
      continue;

    const auto        encrypted        = encrypt_message(info.first, 1, message);
    const auto        nonce            = reinterpret_cast<const unsigned char*>(encrypted.nonce.data());
    const auto&       ciphertext       = encrypted.cipher_text;
          size_t      base64_maxlen    = sodium_base64_ENCODED_LEN(ciphertext.size(), sodium_base64_VARIANT_ORIGINAL);
    std::vector<char> base64_msg(base64_maxlen);

    sodium_bin2base64(base64_msg.data(), base64_maxlen, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size(), sodium_base64_VARIANT_ORIGINAL);

    size_t base64_nonce_maxlen = sodium_base64_ENCODED_LEN(crypto_secretbox_NONCEBYTES, sodium_base64_VARIANT_ORIGINAL);
    std::vector<char> base64_nonce(base64_nonce_maxlen);
    sodium_bin2base64(base64_nonce.data(), base64_nonce_maxlen, nonce, crypto_secretbox_NONCEBYTES, sodium_base64_VARIANT_ORIGINAL);

    json message_json = {
      {"type",      "send_message"     },
      {"recipient", info.first         },
      {"sender",    username_          },
      {"content",   base64_msg.data()  },
      {"nonce",     base64_nonce.data()}};

    do_write(message_json);
  }

}
//-------------------------------------
void client::create_group(const std::string& group_id, const std::string& group_name)
{
  json message = {
    {"type",       "create_group"},
    {"group_id",   group_id      },
    {"group_name", group_name    }};

  do_write(message);
}
//-------------------------------------
void client::join_group(const std::string& group_id)
{
  json message = {{"type", "join_group"}, {"group_id", group_id}};
  do_write(message);
}
//-------------------------------------
encrypt_struct_t client::encrypt_message(const std::string& recipient, int device_id, const std::string& message)
{
  auto get_bundle = [this](const auto& name)
  {
    auto it = user_bundles_.find(name);
    if (it != user_bundles_.end())
      return it->second;
    else
     throw std::runtime_error("User bundle does not exist");
  };

  unsigned char                  nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(nonce, sizeof(nonce));

  encrypt_struct_t ret;
    std::vector<unsigned char> ciphertext(message.size() + crypto_secretbox_MACBYTES);

    if (crypto_secretbox_easy(ciphertext.data(),
                            reinterpret_cast<const unsigned char*>(message.data()),
                            message.size(),
                            nonce,
                            key_) != 0) {
      std::cerr << "Encryption failed" << std::endl;
      throw std::runtime_error{"Encryption failed"};
    }
  ret.cipher_text = {ciphertext.data(), ciphertext.data() + ciphertext.size()};
  ret.nonce       = {nonce, nonce + crypto_secretbox_NONCEBYTES};
  return ret;
}
//-------------------------------------
std::string client::decrypt_message(const std::string& sender, int device_id, const encrypt_struct_t& encrypted)
{

  const auto it = user_bundles_.find(sender);
  if (it == user_bundles_.end())
  {
    std::cerr << "Unable to find sender. Cannot decrypt message" << std::endl;
    return "";
  }
  const auto& ciphertext = encrypted.cipher_text;
  const auto& nonce      = encrypted.nonce;
  const auto& bundle     = it->second;
  size_t bin_len;

  unsigned char decoded_nonce[crypto_secretbox_NONCEBYTES];
  if (sodium_base642bin(decoded_nonce, crypto_secretbox_NONCEBYTES,
                        nonce.c_str(),
                        nonce.size(),
                        nullptr, &bin_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
      std::cerr << "Nonce decoding failed" << std::endl;
      return "";
  }

  std::vector<unsigned char> decoded_ciphertext((ciphertext.size() * 3) / 4);
  if (sodium_base642bin(decoded_ciphertext.data(), decoded_ciphertext.size(),
                        ciphertext.c_str(), ciphertext.size(),
                        nullptr, &bin_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
      std::cerr << "Ciphertext decoding failed" << std::endl;
      return "";
  }
  decoded_ciphertext.resize(bin_len);
  std::vector<unsigned char> decrypted(ciphertext.size());

  if (crypto_secretbox_open_easy(decrypted.data(),
                                reinterpret_cast<const unsigned char*>(decoded_ciphertext.data()),
                                decoded_ciphertext.size(),
                                decoded_nonce,
                                reinterpret_cast<const unsigned char*>(bundle.key.data())) != 0)
  {
    std::cerr << "Decryption failed" << std::endl;
    return "";
  }

  return {decrypted.begin(), decrypted.end()};
}

