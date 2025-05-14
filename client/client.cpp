#include "client.hpp"
#include <iostream>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <random>

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
  if (signal_context_create(&signal_context_, nullptr) != SG_SUCCESS)
    throw std::runtime_error("Failed to create signal context");

  signal_context_set_log_function(signal_context_, log_function);
  signal_crypto_provider crypto_provider = {};
//  signal_crypto_provider crypto_provider = {
    crypto_provider.random_func = [](uint8_t* data, size_t len, void*) -> int {
      try {
        std::random_device rd;
        for (size_t i = 0; i < len; ++i) {
          data[i] = static_cast<uint8_t>(rd());
        }
        return SG_SUCCESS;
      } catch (const std::exception& e) {
        std::cerr << "Random device failed: " << e.what() << std::endl;
        return SG_ERR_UNKNOWN;
      }
    };
    crypto_provider.hmac_sha256_init_func = [](void** hmac_context, const uint8_t* key, size_t key_len, void*) -> int {
      *hmac_context = HMAC_CTX_new();
      if (!*hmac_context) return SG_ERR_NOMEM;
      if (!HMAC_Init_ex(static_cast<HMAC_CTX*>(*hmac_context), key, key_len, EVP_sha256(), nullptr)) {
        HMAC_CTX_free(static_cast<HMAC_CTX*>(*hmac_context));
        return SG_ERR_UNKNOWN;
      }
      return SG_SUCCESS;
    };
    crypto_provider.hmac_sha256_update_func = [](void* hmac_context, const uint8_t* data, size_t data_len, void*) -> int {
      if (!HMAC_Update(static_cast<HMAC_CTX*>(hmac_context), data, data_len)) {
        return SG_ERR_UNKNOWN;
      }
      return SG_SUCCESS;
    };
    crypto_provider.hmac_sha256_final_func = [](void* hmac_context, signal_buffer** output, void*) -> int {
      unsigned int len = 32; // SHA256 output size
      uint8_t* digest = static_cast<uint8_t*>(malloc(len));
      if (!digest) return SG_ERR_NOMEM;
      if (!HMAC_Final(static_cast<HMAC_CTX*>(hmac_context), digest, &len)) {
        free(digest);
        return SG_ERR_UNKNOWN;
      }
      *output = signal_buffer_create(digest, len);
      free(digest);
      return SG_SUCCESS;
    };
    crypto_provider.hmac_sha256_cleanup_func = [](void* hmac_context, void*) {
      HMAC_CTX_free(static_cast<HMAC_CTX*>(hmac_context));
    };
    crypto_provider.encrypt_func = [](signal_buffer** output, int cipher, const uint8_t* key, size_t key_len,
                       const uint8_t* iv, size_t iv_len, const uint8_t* plaintext, size_t plaintext_len,
                       void*) -> int {
      if (cipher != SG_CIPHER_AES_CBC_PKCS5) return SG_ERR_INVAL;
      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      if (!ctx) return SG_ERR_NOMEM;

      int out_len = 0, final_len = 0;
      size_t ciphertext_len = plaintext_len + EVP_MAX_BLOCK_LENGTH;
      uint8_t* ciphertext = static_cast<uint8_t*>(malloc(ciphertext_len));
      if (!ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        return SG_ERR_NOMEM;
      }

      if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) ||
          !EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, plaintext_len) ||
          !EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len)) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return SG_ERR_UNKNOWN;
      }

      *output = signal_buffer_create(ciphertext, out_len + final_len);
      free(ciphertext);
      EVP_CIPHER_CTX_free(ctx);
      return SG_SUCCESS;
    };
    crypto_provider.decrypt_func = [](signal_buffer** output, int cipher, const uint8_t* key, size_t key_len,
                       const uint8_t* iv, size_t iv_len, const uint8_t* ciphertext, size_t ciphertext_len,
                       void*) -> int {
      if (cipher != SG_CIPHER_AES_CBC_PKCS5) return SG_ERR_INVAL;
      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      if (!ctx) return SG_ERR_NOMEM;

      int out_len = 0, final_len = 0;
      uint8_t* plaintext = static_cast<uint8_t*>(malloc(ciphertext_len));
      if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        return SG_ERR_NOMEM;
      }

      if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) ||
          !EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, ciphertext_len) ||
          !EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len)) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return SG_ERR_UNKNOWN;
      }

      *output = signal_buffer_create(plaintext, out_len + final_len);
      free(plaintext);
      EVP_CIPHER_CTX_free(ctx);
      return SG_SUCCESS;
    };
  crypto_provider.user_data = nullptr;

  // Debug: Verify provider
  if (!crypto_provider.random_func) {
    std::cerr << "random_func is null before set" << std::endl;
    throw std::runtime_error("Crypto provider misconfigured");
  }

  signal_context_set_crypto_provider(signal_context_, &crypto_provider);

  std::cout << "Set crypto provider" << std::endl;

  signal_protocol_store_context_create(&store_context_, signal_context_);
  storage_.initialize_signal(store_context_);
  }

void client::do_connect()
{
  auto key_bundle = storage_.generate_key_bundle(signal_context_);
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
