#include "client.hpp"
#include "signal_protocol.h"
#include "storage.hpp"
#include <iostream>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <protocol.h>
#include <session_cipher.h>
#include <session_pre_key.h>
#include <session_builder.h>
#include <random>
#include <stdexcept>

client::client(boost::asio::io_context& io_context, const std::string& host, const std::string& port,
               const std::string& username, const std::string& db_path)
  : io_context_(io_context),
    socket_(io_context),
    storage_(db_path),
    host_(host),
    port_(port),
    username_(username),
    signal_context_(nullptr),
    store_context_(nullptr),
    cli_(*this, username),
    poll_timer_(io_context)
{
  initialize_signal();
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
//--------------------------------------
client::~client()
{
  if (store_context_)
    signal_protocol_store_context_destroy(store_context_);

  if (signal_context_)
    signal_context_destroy(signal_context_);
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
void client::initialize_signal()
{
  if (signal_context_create(&signal_context_, nullptr) != SG_SUCCESS)
    throw std::runtime_error("Failed to create signal context");

  signal_context_set_log_function(signal_context_, log_function);
  signal_crypto_provider crypto_provider = {};

  crypto_provider.random_func = [](uint8_t* data, size_t len, void*) -> int
  {
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

  crypto_provider.hmac_sha256_init_func = [](void** hmac_context, const uint8_t* key, size_t key_len, void*) -> int
  {
    *hmac_context = HMAC_CTX_new();
    if (!*hmac_context) return SG_ERR_NOMEM;
    if (!HMAC_Init_ex(static_cast<HMAC_CTX*>(*hmac_context), key, key_len, EVP_sha256(), nullptr))
    {
      HMAC_CTX_free(static_cast<HMAC_CTX*>(*hmac_context));
      return SG_ERR_UNKNOWN;
    }

    return SG_SUCCESS;
  };

  crypto_provider.hmac_sha256_update_func = [](void* hmac_context, const uint8_t* data, size_t data_len, void*) -> int
  {
    if (!HMAC_Update(static_cast<HMAC_CTX*>(hmac_context), data, data_len))
      return SG_ERR_UNKNOWN;
    return SG_SUCCESS;
  };

  crypto_provider.hmac_sha256_final_func = [](void* hmac_context, signal_buffer** output, void*) -> int
  {
    unsigned int len = 32; // SHA256 output size
    uint8_t* digest = static_cast<uint8_t*>(malloc(len));
    if (!digest) return SG_ERR_NOMEM;
    if (!HMAC_Final(static_cast<HMAC_CTX*>(hmac_context), digest, &len))
    {
      free(digest);
      return SG_ERR_UNKNOWN;
    }

    *output = signal_buffer_create(digest, len);
    free(digest);
    return SG_SUCCESS;
  };

  crypto_provider.hmac_sha256_cleanup_func = [](void* hmac_context, void*)
  {
    HMAC_CTX_free(static_cast<HMAC_CTX*>(hmac_context));
  };

  crypto_provider.encrypt_func = [](signal_buffer** output, int cipher, const uint8_t* key, size_t key_len,
                     const uint8_t* iv, size_t iv_len, const uint8_t* plaintext, size_t plaintext_len,
                     void*) -> int
  {
    if (cipher != SG_CIPHER_AES_CBC_PKCS5) return SG_ERR_INVAL;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx) return SG_ERR_NOMEM;

    int      out_len = 0, final_len = 0;
    size_t   ciphertext_len = plaintext_len + EVP_MAX_BLOCK_LENGTH;
    uint8_t* ciphertext = static_cast<uint8_t*>(malloc(ciphertext_len));

    if (!ciphertext)
    {
      EVP_CIPHER_CTX_free(ctx);
      return SG_ERR_NOMEM;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) ||
        !EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, plaintext_len) ||
        !EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len))
    {
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
                     void*) -> int
  {
    if (cipher != SG_CIPHER_AES_CBC_PKCS5) return SG_ERR_INVAL;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx)
      return SG_ERR_NOMEM;

    int out_len = 0, final_len = 0;
    uint8_t* plaintext = static_cast<uint8_t*>(malloc(ciphertext_len));
    if (!plaintext)
    {
      EVP_CIPHER_CTX_free(ctx);
      return SG_ERR_NOMEM;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) ||
        !EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, ciphertext_len) ||
        !EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len))
    {
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

  signal_context_set_crypto_provider  (signal_context_, &crypto_provider);
  signal_protocol_store_context_create(&store_context_, signal_context_);
  storage_.initialize_signal(store_context_);
}
//-------------------------------------
void client::do_connect()
{
  std::cout << "Passing context to storage_: " << signal_context_ << std::endl;
  key_bundle_ = storage_.generate_key_bundle(signal_context_);
  user_bundles_.insert_or_assign(username_, key_bundle_);
  auto encrypted_message = encrypt_message(username_, 1, "This is an unencrypted message!");
  std::cout << "Encrypted: " << encrypted_message << std::endl;
  auto decrypted_message = decrypt_message(username_, 1, encrypted_message);
  std::cout << "Decrypted: " << decrypted_message << std::endl;

//  start_session(
//  std::string identity_key; // Base64-encoded identity public key
//  std::string signed_pre_key; // Base64-encoded signed pre-key public key
//  std::string signed_pre_key_public; // Base64-encoded signed pre-key public key (optional, can remove if redundant)
//  uint32_t    signed_pre_key_id; // Signed pre-key ID
//  std::string signed_pre_key_signature; // Base64-encoded signature
//  std::vector<std::string> one_time_pre_keys; // Base64-encoded one-time pre-key public keys
//  uint32_t registration_id; // Registration ID

  json register_message = {
    {"type", "register"},
    {"username", username_},
    {"identity_key", key_bundle_.identity_key},
    {"signed_pre_key", key_bundle_.signed_pre_key},
    {"signed_pre_key_public", key_bundle_.signed_pre_key_public},
    {"signed_pre_key_id", key_bundle_.signed_pre_key_id},
    {"signed_pre_key_signature", key_bundle_.signed_pre_key_signature},
    {"one_time_pre_keys", key_bundle_.one_time_pre_keys},
    {"registration_id", key_bundle_.registration_id}
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
  std::cout << "server message:\n" << message.dump() << std::endl;
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
      std::string sender = msg.value("sender", "");
      std::string ciphertext = msg.value("content", "");
      std::string plaintext = decrypt_message(sender, 1, ciphertext);
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
    auto bundle = user_key_bundle{ message.value("identity_key", ""), message.value("signed_pre_key", "")};
    for (const auto& pre_key : message["one_time_pre_keys"])
      bundle.one_time_pre_keys.push_back(pre_key.get<std::string>());
    if (!bundle.identity_key.empty())
      user_bundles_.insert_or_assign(message.value("username", ""), bundle);
  }
}
//-------------------------------------
void client::send_message(const std::string& recipient, const std::string& message)
{
  for (const auto& info : user_bundles_)
  {
    std::string ciphertext = encrypt_message(info.first, 1, message);
    json message_json = {
      {"type", "send_message"},
      {"recipient", recipient},
      {"sender", username_},
      {"content", ciphertext}
    };
    do_write(message_json);
  }

}
//-------------------------------------
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
//-------------------------------------
void client::join_group(const std::string& group_id)
{
  json message = {{"type", "join_group"}, {"group_id", group_id}};
  do_write(message);
}
//-------------------------------------
std::string client::encrypt_message(const std::string& recipient, int device_id, const std::string& message)
{
  auto get_bundle = [this](const auto& name)
  {
    auto it = user_bundles_.find(name);
    if (it != user_bundles_.end())
      return it->second;
    else
     throw std::runtime_error("User bundle does not exist");
  };

//  bool session_initialized = false;
  std::cout << "Encrypting message and signal context is " << signal_context_ << std::endl;
  // Create session if not exists
  signal_protocol_address address = { recipient.c_str(), recipient.size(), device_id };

//  // Check if session exists
//  signal_buffer* session_record = nullptr;
//  if (storage_.session_store_load_session(&session_record, nullptr, &address, this) < 1)
//  {
//    std::cerr << "No session for " << recipient << ", starting session" << std::endl;
//    const auto bundle = get_bundle(recipient);
//    start_session(recipient, 1, bundle);
// //   session_initialized = true;
//  }
//  else
//  {
//    signal_buffer_free(session_record);
//    std::cerr << "Session exists for " << recipient << std::endl;
//  }

  session_cipher* cipher = nullptr;

  if (session_cipher_create(&cipher, store_context_, &address, signal_context_) != SG_SUCCESS)
    throw std::runtime_error("Failed to create session cipher");

  // If session was just initialized, reload to ensure consistency
//  if (session_initialized) {
//    signal_buffer* verify_record = nullptr;
//    if (storage_.session_store_load_session(&verify_record, nullptr, &address, this) < 1) {
//      session_cipher_free(cipher);
//      throw std::runtime_error("Session not properly stored after start_session");
//    }
//    std::cerr << "Verified session after start_session (len=" << signal_buffer_len(verify_record) << ")" << std::endl;
//    signal_buffer_free(verify_record);
//  }

  // Encrypt message
  ciphertext_message* encrypted_message = nullptr;
  int result = session_cipher_encrypt(cipher,
                                    reinterpret_cast<const uint8_t*>(message.c_str()),
                                    message.size(),
                                    &encrypted_message);
  if (result != SG_SUCCESS)
  {
    session_cipher_free(cipher);
    throw std::runtime_error("Failed to encrypt message");
  }

  // Serialize encrypted message
  signal_buffer* serialized = ciphertext_message_get_serialized(encrypted_message);
  if (!serialized)
  {
    SIGNAL_UNREF(encrypted_message);
    session_cipher_free(cipher);
    throw std::runtime_error("Failed to serialize encrypted message");
  }

  std::string ciphertext = base64_encode(signal_buffer_data(serialized), signal_buffer_len(serialized));

  // Cleanup
  SIGNAL_UNREF(encrypted_message);
  session_cipher_free(cipher);

  return ciphertext;
}
//-------------------------------------
std::string client::decrypt_message(const std::string& sender, int device_id, const std::string& ciphertext)
{
  // Decode base64 ciphertext
  std::vector<uint8_t> decoded = base64_decode(ciphertext);
  if (decoded.empty())
    throw std::runtime_error("Failed to decode ciphertext");

  // Create session cipher
  signal_protocol_address address = { sender.c_str(), sender.size(), device_id };
  session_cipher* cipher = nullptr;
  if (session_cipher_create(&cipher, store_context_, &address, signal_context_) != SG_SUCCESS)
    throw std::runtime_error("Failed to create session cipher");

// Deserialize ciphertext message
  ciphertext_message* encrypted_message = nullptr;
  signal_message* signal_msg = nullptr;
  pre_key_signal_message* pre_key_msg = nullptr;

  // Try deserializing as regular signal message
  int result = signal_message_deserialize(&signal_msg, decoded.data(), decoded.size(), signal_context_);
  if (result == SG_SUCCESS)
    encrypted_message = reinterpret_cast<ciphertext_message*>(signal_msg);
  else
  {
    // Try deserializing as pre-key signal message
    result = pre_key_signal_message_deserialize(&pre_key_msg, decoded.data(), decoded.size(), signal_context_);
    if (result != SG_SUCCESS)
    {
      session_cipher_free(cipher);
      throw std::runtime_error("Failed to deserialize ciphertext");
    }

    encrypted_message = reinterpret_cast<ciphertext_message*>(pre_key_msg);
  }

  // Decrypt message
  signal_buffer* plaintext_buf = nullptr;
  int decrypt_result;

  if (signal_msg)
    decrypt_result = session_cipher_decrypt_signal_message(cipher, signal_msg, nullptr, &plaintext_buf);
  else if (pre_key_msg)
    decrypt_result = session_cipher_decrypt_pre_key_signal_message(cipher, pre_key_msg, nullptr, &plaintext_buf);
  else
    throw std::runtime_error("Failed to deserialize signal or pre_key message");

  if (decrypt_result != SG_SUCCESS)
  {
    SIGNAL_UNREF(encrypted_message);
    session_cipher_free(cipher);
    signal_buffer_free(plaintext_buf);
    throw std::runtime_error("Failed to decrypt message");
  }

  std::string plaintext(reinterpret_cast<char*>(signal_buffer_data(plaintext_buf)), signal_buffer_len(plaintext_buf));

  // Cleanup
  signal_buffer_free(plaintext_buf);
  SIGNAL_UNREF(signal_msg);
  SIGNAL_UNREF(pre_key_msg);
  session_cipher_free(cipher);

  return plaintext;
}

void client::start_session(const std::string& recipient_id, int device_id, const user_key_bundle& bundle)
{
    std::cerr << "Starting session for " << recipient_id << ", device_id=" << device_id << std::endl;
  std::cerr << "Bundle: identity=" << bundle.identity_key
            << ", signed_pre_key=" << bundle.signed_pre_key
            << ", signature=" << bundle.signed_pre_key_signature
            << ", pre_keys=" << bundle.one_time_pre_keys.size()
            << ", reg_id=" << bundle.registration_id << std::endl;

  // Decode key bundle components
  std::vector<uint8_t> identity_key = base64_decode(bundle.identity_key);
  std::vector<uint8_t> signed_pre_key = base64_decode(bundle.signed_pre_key);
  std::vector<uint8_t> signed_pre_key_signature = base64_decode(bundle.signed_pre_key_signature);
  std::vector<uint8_t> pre_key = bundle.one_time_pre_keys.empty() ? std::vector<uint8_t>() : base64_decode(bundle.one_time_pre_keys[0]);

  // Debug key sizes
  std::cerr << "Identity Key Size: " << identity_key.size() << ", First Byte: 0x" << std::hex << (int)identity_key[0] << std::endl;
  std::cerr << "Signed Pre Key Size: " << signed_pre_key.size() << ", First Byte: 0x" << std::hex << (int)signed_pre_key[0] << std::endl;
  std::cerr << "Signature Size: " << signed_pre_key_signature.size() << std::endl;
  if (!pre_key.empty()) {
    std::cerr << "Pre Key Size: " << pre_key.size() << ", First Byte: 0x" << std::hex << (int)pre_key[0] << std::endl;
  }

  // Create public keys
  ec_public_key* identity_pub = nullptr;
  ec_public_key* signed_pre_key_pub = nullptr;
  ec_public_key* pre_key_pub = nullptr;
  if (curve_decode_point(&identity_pub, identity_key.data(), identity_key.size(), signal_context_) != SG_SUCCESS) {
    throw std::runtime_error("Failed to decode identity key");
  }
  if (curve_decode_point(&signed_pre_key_pub, signed_pre_key.data(), signed_pre_key.size(), signal_context_) != SG_SUCCESS) {
    SIGNAL_UNREF(identity_pub);
    throw std::runtime_error("Failed to decode signed pre-key");
  }
  if (!pre_key.empty()) {
    if (curve_decode_point(&pre_key_pub, pre_key.data(), pre_key.size(), signal_context_) != SG_SUCCESS) {
      SIGNAL_UNREF(identity_pub);
      SIGNAL_UNREF(signed_pre_key_pub);
      throw std::runtime_error("Failed to decode one-time pre-key");
    }
  }

  // Create pre-key bundle
  session_pre_key_bundle* pre_key_bundle = nullptr;
  if (session_pre_key_bundle_create(&pre_key_bundle,
                                   bundle.registration_id,
                                   device_id,
                                   pre_key.empty() ? 0 : 1, // Pre-key ID (assuming 1 for first pre-key)
                                   pre_key_pub,
                                   bundle.signed_pre_key_id,
                                   signed_pre_key_pub,
                                   signed_pre_key_signature.data(),
                                   signed_pre_key_signature.size(),
                                   identity_pub) != SG_SUCCESS) {
    SIGNAL_UNREF(identity_pub);
    SIGNAL_UNREF(signed_pre_key_pub);
    SIGNAL_UNREF(pre_key_pub);
    throw std::runtime_error("Failed to create pre-key bundle");
  }

  // Create session builder
  signal_protocol_address address = {recipient_id.c_str(), recipient_id.size(), device_id};
  session_builder* builder = nullptr;
//  if (session_builder_create(&builder, store_context_, signal_context_) != SG_SUCCESS) {
  if (session_builder_create(&builder, store_context_, &address, signal_context_) != SG_SUCCESS) {
    SIGNAL_UNREF(pre_key_bundle);
    SIGNAL_UNREF(identity_pub);
    SIGNAL_UNREF(signed_pre_key_pub);
    SIGNAL_UNREF(pre_key_pub);
    throw std::runtime_error("Failed to create session builder");
  }

  // Save identity key to ensure trust
  if (signal_protocol_identity_save_identity(store_context_, &address, identity_pub) != SG_SUCCESS) {
    session_builder_free(builder);
    SIGNAL_UNREF(pre_key_bundle);
    SIGNAL_UNREF(identity_pub);
    SIGNAL_UNREF(signed_pre_key_pub);
    SIGNAL_UNREF(pre_key_pub);
    throw std::runtime_error("Failed to save identity key");
  }

  // Process pre-key bundle
  int result = session_builder_process_pre_key_bundle(builder, pre_key_bundle);
  if (result != SG_SUCCESS) {
    std::cerr << "Failed to process pre-key bundle, result=" << result << std::endl;
    session_builder_free(builder);
    SIGNAL_UNREF(pre_key_bundle);
    SIGNAL_UNREF(identity_pub);
    SIGNAL_UNREF(signed_pre_key_pub);
    SIGNAL_UNREF(pre_key_pub);
    throw std::runtime_error("Failed to process pre-key bundle: " + std::to_string(result));
  }

  // Cleanup
  session_builder_free(builder);
  SIGNAL_UNREF(pre_key_bundle);
  SIGNAL_UNREF(identity_pub);
  SIGNAL_UNREF(signed_pre_key_pub);
  SIGNAL_UNREF(pre_key_pub);
  std::cerr << "Session started for " << recipient_id << std::endl;
}

