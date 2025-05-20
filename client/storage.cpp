#include "storage.hpp"
#include <iostream>
#include "key_helper.h"
#include "signal_protocol.h"
#include "curve.h"
#include "session_pre_key.h"

std::map<std::string, session_t> storage::sessions_ = {};

std::string base64_encode(const uint8_t* data, size_t len)
{
  static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string result;
  result.reserve((len + 2) / 3 * 4);
  for (size_t i = 0; i < len; i += 3) {
    uint32_t triplet = (data[i] << 16) + (i + 1 < len ? data[i + 1] << 8 : 0) + (i + 2 < len ? data[i + 2] : 0);
    result.push_back(base64_chars[(triplet >> 18) & 63]);
    result.push_back(base64_chars[(triplet >> 12) & 63]);
    result.push_back(i + 1 < len ? base64_chars[(triplet >> 6) & 63] : '=');
    result.push_back(i + 2 < len ? base64_chars[triplet & 63] : '=');
  }
  return result;
}

std::vector<uint8_t> base64_decode(const std::string& input)
{
  static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::vector<uint8_t> result;
  result.reserve(input.size() * 3 / 4);

  for (size_t i = 0; i < input.size(); i += 4) {
    uint32_t sextet_a = input[i] == '=' ? 0 : base64_chars.find(input[i]);
    uint32_t sextet_b = input[i + 1] == '=' ? 0 : base64_chars.find(input[i + 1]);
    uint32_t sextet_c = input[i + 2] == '=' ? 0 : base64_chars.find(input[i + 2]);
    uint32_t sextet_d = input[i + 3] == '=' ? 0 : base64_chars.find(input[i + 3]);

    uint32_t triplet = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;
    result.push_back((triplet >> 16) & 255);
    if (input[i + 2] != '=') result.push_back((triplet >> 8) & 255);
    if (input[i + 3] != '=') result.push_back(triplet & 255);
  }
  return result;
}

storage::storage(const std::string& db_path)
  : db_(db_path, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE)
{
  db_.exec("PRAGMA cache_size = -20000;"); // Increase cache size (20MB)
  db_.exec("CREATE TABLE IF NOT EXISTS identity_key ("
           "key_pair BLOB,"
           "registration_id INTEGER)");
  db_.exec("CREATE TABLE IF NOT EXISTS identity_keys ("
           "recipient_id TEXT PRIMARY KEY,"
           "public_key BLOB)");
  db_.exec("CREATE TABLE IF NOT EXISTS signed_pre_key ("
           "key_id INTEGER PRIMARY KEY,"
           "key_pair BLOB,"
           "signature BLOB)");
  db_.exec("CREATE TABLE IF NOT EXISTS one_time_pre_keys ("
           "key_id INTEGER PRIMARY KEY,"
           "key_pair BLOB)");
  db_.exec("CREATE TABLE IF NOT EXISTS sessions ("
           "recipient_id TEXT PRIMARY KEY,"
           "session_record BLOB)");
  db_.exec("CREATE TABLE IF NOT EXISTS groups ("
           "group_id TEXT PRIMARY KEY,"
           "group_name TEXT)");
  db_.exec("CREATE TABLE IF NOT EXISTS group_members ("
           "group_id TEXT,"
           "username TEXT,"
           "FOREIGN KEY(group_id) REFERENCES groups(group_id))");
}

storage::~storage()
{
}

void storage::initialize_signal(signal_protocol_store_context* store_ctx)
{
  signal_protocol_identity_key_store identity_store = {
   .get_identity_key_pair = identity_key_store_get_identity_key_pair,
   .get_local_registration_id = identity_key_store_get_local_registration_id,
   .save_identity = identity_key_store_save_identity,
   .is_trusted_identity = identity_key_store_is_trusted_identity,
   .destroy_func = nullptr,
   .user_data = this
  };
  signal_protocol_pre_key_store pre_key_store = {
    .load_pre_key = pre_key_store_load_pre_key,
    .store_pre_key = pre_key_store_store_pre_key,
    .contains_pre_key = pre_key_store_contains_pre_key,
    .remove_pre_key = pre_key_store_remove_pre_key,
    .destroy_func = nullptr,
    .user_data = this,
  };
  signal_protocol_signed_pre_key_store signed_pre_key_store = {
    .load_signed_pre_key = signed_pre_key_store_load_signed_pre_key,
    .store_signed_pre_key = signed_pre_key_store_store_signed_pre_key,
    .contains_signed_pre_key = signed_pre_key_store_contains_signed_pre_key,
    .destroy_func = nullptr,
    .user_data = this
  };
  signal_protocol_session_store session_store = {
    .load_session_func = session_store_load_session,
    .get_sub_device_sessions_func = [](signal_int_list** sessions, const char* name, size_t name_len, void* user_data) -> int {
      *sessions = signal_int_list_alloc();
      if (!*sessions) return SG_ERR_NOMEM;
      signal_int_list_push_back(*sessions, 1); // Single device per user
      return SG_SUCCESS;
    },
    .store_session_func = session_store_store_session,
    .contains_session_func = [](const signal_protocol_address* address, void* user_data) -> int {
      auto* storage = static_cast<class storage*>(user_data);
      try {
        std::string recipient_id(address->name, address->name_len);
        SQLite::Statement query(storage->db_, "SELECT 1 FROM sessions WHERE recipient_id = ?");
        query.bind(1, recipient_id);
        return query.executeStep() ? 1 : 0;
      } catch (const SQLite::Exception& e) {
        std::cerr << "SQLite error in contains_session: " << e.what() << std::endl;
        return 0;
      }
    },
    .delete_session_func = [](const signal_protocol_address* address, void* user_data) -> int {
      auto* storage = static_cast<class storage*>(user_data);
      try {
        std::string recipient_id(address->name, address->name_len);
        SQLite::Statement del(storage->db_, "DELETE FROM sessions WHERE recipient_id = ?");
        del.bind(1, recipient_id);
        del.exec();
        return SG_SUCCESS;
      } catch (const SQLite::Exception& e) {
        std::cerr << "SQLite error in delete_session: " << e.what() << std::endl;
        return SG_ERR_UNKNOWN;
      }
    },
    .delete_all_sessions_func = [](const char* name, size_t name_len, void* user_data) -> int {
      auto* storage = static_cast<class storage*>(user_data);
      try {
        std::string recipient_id(name, name_len);
        SQLite::Statement del(storage->db_, "DELETE FROM sessions WHERE recipient_id = ?");
        del.bind(1, recipient_id);
        del.exec();
        return SG_SUCCESS;
      } catch (const SQLite::Exception& e) {
        std::cerr << "SQLite error in delete_all_sessions: " << e.what() << std::endl;
        return SG_ERR_UNKNOWN;
      }
    },
    .destroy_func = nullptr,
    .user_data = this
  };

  signal_protocol_store_context_set_identity_key_store(store_ctx, &identity_store);
  signal_protocol_store_context_set_pre_key_store(store_ctx, &pre_key_store);
  signal_protocol_store_context_set_signed_pre_key_store(store_ctx, &signed_pre_key_store);
  signal_protocol_store_context_set_session_store(store_ctx, &session_store);
}

user_key_bundle storage::generate_key_bundle(signal_context* global_context)
{
  std::cout << "Received global_context in storage: " << global_context << std::endl;
  user_key_bundle bundle;

  // Generate registration ID
  uint32_t registration_id = 0;
  if (signal_protocol_key_helper_generate_registration_id(&registration_id, 0, global_context) != SG_SUCCESS) {
    throw std::runtime_error("Failed to generate registration ID");
  }
  bundle.registration_id = registration_id;

  // Generate identity key pair
  ratchet_identity_key_pair* identity_key_pair = nullptr;
  if (signal_protocol_key_helper_generate_identity_key_pair(&identity_key_pair, global_context) != SG_SUCCESS) {
    throw std::runtime_error("Failed to generate identity key pair");
  }

  ec_public_key* identity_public = ratchet_identity_key_pair_get_public(identity_key_pair);
  ec_private_key* identity_private = ratchet_identity_key_pair_get_private(identity_key_pair);

  // Serialize public key for bundle
  signal_buffer* public_buf = nullptr;
  if (ec_public_key_serialize(&public_buf, identity_public) != SG_SUCCESS) {
    SIGNAL_UNREF(identity_key_pair);
    throw std::runtime_error("Failed to serialize public key");
  }
  bundle.identity_key = base64_encode(signal_buffer_data(public_buf), signal_buffer_len(public_buf));

  // Serialize private key for storage
  signal_buffer* private_buf = nullptr;
  if (ec_private_key_serialize(&private_buf, identity_private) != SG_SUCCESS) {
    signal_buffer_free(public_buf);
    SIGNAL_UNREF(identity_key_pair);
    throw std::runtime_error("Failed to serialize private key");
  }
  std::string key_pair;
  key_pair.append(reinterpret_cast<char*>(signal_buffer_data(public_buf)), signal_buffer_len(public_buf));
  key_pair.append(reinterpret_cast<char*>(signal_buffer_data(private_buf)), signal_buffer_len(private_buf));
  try {
    SQLite::Statement insert_identity(db_, "INSERT INTO identity_key (key_pair, registration_id) VALUES (?, ?)");
    insert_identity.bind(1, key_pair);
    insert_identity.bind(2, static_cast<int64_t>(registration_id));
    insert_identity.exec();
  } catch (const SQLite::Exception& e) {
    signal_buffer_free(public_buf);
    signal_buffer_free(private_buf);
    SIGNAL_UNREF(identity_key_pair);
    throw std::runtime_error("SQLite error in storing identity key: " + std::string(e.what()));
  }
  signal_buffer_free(public_buf);
  public_buf = nullptr;
  signal_buffer_free(private_buf);
  private_buf = nullptr;

  // Generate signed pre-key
  uint32_t signed_pre_key_id = 1;
  session_signed_pre_key* signed_pre_key = nullptr;
  signal_buffer* signature_buf = nullptr;
  ec_key_pair* ec_pair = nullptr;
  uint64_t timestamp = time(nullptr);

  if (curve_generate_key_pair(global_context, &ec_pair) != SG_SUCCESS) {
    SIGNAL_UNREF(identity_key_pair);
    throw std::runtime_error("Failed to generate key pair for signed pre-key");
  }

  ec_public_key* public_key = ec_key_pair_get_public(ec_pair);
  if (ec_public_key_serialize(&public_buf, public_key) != SG_SUCCESS) {
    SIGNAL_UNREF(ec_pair);
    SIGNAL_UNREF(identity_key_pair);
    throw std::runtime_error("Failed to serialize signed pre-key public key");
  }

  // Set public key and signature for bundle
  bundle.signed_pre_key = base64_encode(signal_buffer_data(public_buf), signal_buffer_len(public_buf));
  bundle.signed_pre_key_public = bundle.signed_pre_key; // Keep for compatibility, can remove later
  bundle.signed_pre_key_id = signed_pre_key_id;

  ec_private_key* identity_private_key = ratchet_identity_key_pair_get_private(identity_key_pair);
  if (curve_calculate_signature(global_context, &signature_buf, identity_private_key,
                                signal_buffer_data(public_buf), signal_buffer_len(public_buf)) != SG_SUCCESS) {
    signal_buffer_free(public_buf);
    SIGNAL_UNREF(ec_pair);
    SIGNAL_UNREF(identity_key_pair);
    throw std::runtime_error("Failed to calculate signature for signed pre-key");
  }
  bundle.signed_pre_key_signature = base64_encode(signal_buffer_data(signature_buf), signal_buffer_len(signature_buf));

  // Create session_signed_pre_key for storage
  if (session_signed_pre_key_create(&signed_pre_key, signed_pre_key_id, timestamp, ec_pair,
                                   signal_buffer_data(signature_buf), signal_buffer_len(signature_buf)) != SG_SUCCESS) {
    signal_buffer_free(public_buf);
    signal_buffer_free(signature_buf);
    SIGNAL_UNREF(ec_pair);
    SIGNAL_UNREF(identity_key_pair);
    throw std::runtime_error("Failed to create signed pre-key");
  }

  // Store signed pre-key in database
  signal_buffer* signed_pre_key_buf = nullptr;
  if (session_signed_pre_key_serialize(&signed_pre_key_buf, signed_pre_key) != SG_SUCCESS) {
    signal_buffer_free(public_buf);
    signal_buffer_free(signature_buf);
    SIGNAL_UNREF(signed_pre_key);
    SIGNAL_UNREF(ec_pair);
    SIGNAL_UNREF(identity_key_pair);
    throw std::runtime_error("Failed to serialize signed pre-key");
  }

  try
  {
    std::cout << "Inserting into signed_pre_key the following key_id: " << signed_pre_key_id << std::endl;

    SQLite::Statement insert_signed(db_, "INSERT INTO signed_pre_key (key_id, key_pair) VALUES (?, ?)");
    insert_signed.bind(1, static_cast<int64_t>(signed_pre_key_id));
    insert_signed.bind(2, std::string(reinterpret_cast<char*>(signal_buffer_data(signed_pre_key_buf)),
                                     signal_buffer_len(signed_pre_key_buf)));
    insert_signed.exec();
  } catch (const SQLite::Exception& e)
  {
    std::cerr << "Failed to insert into signed_pre_key table: " << e.what() << std::endl;
    signal_buffer_free(signed_pre_key_buf);
    signal_buffer_free(public_buf);
    signal_buffer_free(signature_buf);
    SIGNAL_UNREF(signed_pre_key);
    SIGNAL_UNREF(ec_pair);
    SIGNAL_UNREF(identity_key_pair);
    throw std::runtime_error("SQLite error in storing signed pre-key: " + std::string(e.what()));
  }

  signal_buffer_free(signed_pre_key_buf);
  signal_buffer_free(public_buf);
  signal_buffer_free(signature_buf);
  SIGNAL_UNREF(signed_pre_key);
  // Note: ec_pair is owned by signed_pre_key, so not unreferenced separately

  // Generate one-time pre-keys
  signal_protocol_key_helper_pre_key_list_node* pre_keys_head = nullptr;
  if (signal_protocol_key_helper_generate_pre_keys(&pre_keys_head, 0, 10, global_context) != SG_SUCCESS) {
    SIGNAL_UNREF(identity_key_pair);
    throw std::runtime_error("Failed to generate one-time pre-keys");
  }
  signal_protocol_key_helper_pre_key_list_node* node = pre_keys_head;
  while (node) {
    session_pre_key* pre_key = signal_protocol_key_helper_key_list_element(node);
    uint32_t pre_key_id = session_pre_key_get_id(pre_key);
    signal_buffer* pre_key_buf = nullptr;
    if (ec_public_key_serialize(&pre_key_buf, ec_key_pair_get_public(session_pre_key_get_key_pair(pre_key))) != SG_SUCCESS) {
      signal_protocol_key_helper_key_list_free(pre_keys_head);
      SIGNAL_UNREF(identity_key_pair);
      throw std::runtime_error("Failed to serialize one-time pre-key");
    }
    bundle.one_time_pre_keys.push_back(base64_encode(signal_buffer_data(pre_key_buf), signal_buffer_len(pre_key_buf)));

    // Store one-time pre-key in database (full session_pre_key)
    signal_buffer* pre_key_full_buf = nullptr;
    if (session_pre_key_serialize(&pre_key_full_buf, pre_key) != SG_SUCCESS) {
      signal_buffer_free(pre_key_buf);
      signal_protocol_key_helper_key_list_free(pre_keys_head);
      SIGNAL_UNREF(identity_key_pair);
      throw std::runtime_error("Failed to serialize one-time pre-key for storage");
    }
    try {
      SQLite::Statement insert_pre(db_, "INSERT INTO one_time_pre_keys (key_id, key_pair) VALUES (?, ?)");
      insert_pre.bind(1, static_cast<int64_t>(pre_key_id));
      insert_pre.bind(2, std::string(reinterpret_cast<char*>(signal_buffer_data(pre_key_full_buf)),
                                    signal_buffer_len(pre_key_full_buf)));
      insert_pre.exec();
    } catch (const SQLite::Exception& e) {
      signal_buffer_free(pre_key_buf);
      signal_buffer_free(pre_key_full_buf);
      signal_protocol_key_helper_key_list_free(pre_keys_head);
      SIGNAL_UNREF(identity_key_pair);
      throw std::runtime_error("SQLite error in storing one-time pre-key: " + std::string(e.what()));
    }
    signal_buffer_free(pre_key_buf);
    signal_buffer_free(pre_key_full_buf);
    node = signal_protocol_key_helper_key_list_next(node);
  }

  // Cleanup
  signal_protocol_key_helper_key_list_free(pre_keys_head);
  SIGNAL_UNREF(identity_key_pair);

  std::cout << "Returning bundle with context: " << global_context << std::endl;
  return bundle;
}

void storage::save_session(const std::string& recipient, const std::string& session_data)
{
  SQLite::Statement insert(db_, "INSERT OR REPLACE INTO sessions (recipient, session_data) VALUES (?, ?)");
  insert.bind(1, recipient);
  insert.bind(2, session_data);
  insert.exec();
}

std::string storage::load_session(const std::string& recipient)
{
  std::cout << "Getting session for " << recipient << std::endl;
  SQLite::Statement query(db_, "SELECT session_data FROM sessions WHERE recipient = ?");
  query.bind(1, recipient);
  if (query.executeStep()) {
    return query.getColumn(0).getString();
  }
  return "";
}

void storage::save_group(const std::string& group_id, const std::string& group_name)
{
  SQLite::Statement insert(db_, "INSERT OR REPLACE INTO groups (group_id, group_name) VALUES (?, ?)");
  insert.bind(1, group_id);
  insert.bind(2, group_name);
  insert.exec();
}

std::vector<std::string> storage::get_group_members(const std::string& group_id)
{
  std::vector<std::string> members;
  SQLite::Statement query(db_, "SELECT username FROM group_members WHERE group_id = ?");
  query.bind(1, group_id);
  while (query.executeStep()) {
    members.push_back(query.getColumn(0).getString());
  }
  return members;
}

// Signal Protocol callbacks (simplified placeholders)
int storage::identity_key_store_get_identity_key_pair(signal_buffer** public_buf, signal_buffer** private_buf, void* user_data)
{
  auto* storage = static_cast<class storage*>(user_data);
  try {
    SQLite::Statement query(storage->db_, "SELECT key_pair FROM identity_key LIMIT 1");
    if (!query.executeStep()) {
      return SG_ERR_UNKNOWN;
    }
    std::string key_pair = query.getColumn(0).getString();
    *public_buf  = signal_buffer_create(reinterpret_cast<const uint8_t*>(key_pair.data()),      33);
    *private_buf = signal_buffer_create(reinterpret_cast<const uint8_t*>(key_pair.data()) + 33, 32);

    if (!*public_buf || !*private_buf) {
      signal_buffer_free(*public_buf);
      signal_buffer_free(*private_buf);
      *public_buf  = nullptr;
      *private_buf = nullptr;
      std::cerr << "Memory allocation failed for identity key buffers" << std::endl;
      return SG_ERR_NOMEM;
    }

    return SG_SUCCESS;
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQLite error in get_identity_key_pair: " << e.what() << std::endl;
    return SG_ERR_UNKNOWN;
  }

  return SG_SUCCESS;
}

int storage::identity_key_store_get_local_registration_id(void* ctx, uint32_t* idp)
{
  auto* storage = static_cast<class storage*>(ctx);
  try {
    SQLite::Statement query(storage->db_, "SELECT registration_id FROM identity_key LIMIT 1");
    if (!query.executeStep()) {
      *idp = 1; // Default ID
      return SG_SUCCESS;
    }
    *idp = query.getColumn(0).getInt();
    return SG_SUCCESS;
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQLite error in get_local_registration_id: " << e.what() << std::endl;
    return SG_ERR_UNKNOWN;
  }

  return SG_SUCCESS;
}

int storage::identity_key_store_save_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
  auto* storage = static_cast<class storage*>(user_data);
  try {
    std::string recipient_id(address->name, address->name_len);
    SQLite::Statement insert(storage->db_, "INSERT OR REPLACE INTO identity_keys (recipient_id, public_key) VALUES (?, ?)");
    insert.bind(1, recipient_id);
    insert.bind(2, std::string(reinterpret_cast<char*>(key_data), key_len));
    insert.exec();
    return SG_SUCCESS;
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQLite error in save_identity: " << e.what() << std::endl;
    return SG_ERR_UNKNOWN;
  }
  return SG_SUCCESS;
}

int storage::identity_key_store_is_trusted_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
  auto* storage = static_cast<class storage*>(user_data);
  try {
    std::string recipient_id(address->name, address->name_len);
    SQLite::Statement query(storage->db_, "SELECT public_key FROM identity_keys WHERE recipient_id = ?");
    query.bind(1, recipient_id);
    if (!query.executeStep()) {
      return 1; // New key, trust by default
    }
    std::string stored_key = query.getColumn(0).getString();
    if (stored_key == std::string(reinterpret_cast<char*>(key_data), key_len)) {
      return 1;
    }
    return SG_ERR_INVALID_KEY; // Key mismatch
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQLite error in is_trusted_identity: " << e.what() << std::endl;
    return SG_ERR_UNKNOWN;
  }

  return SG_SUCCESS;
}

int storage::pre_key_store_load_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data)
{
  auto* storage = static_cast<class storage*>(user_data);
  try {
    SQLite::Statement query(storage->db_, "SELECT key_pair FROM one_time_pre_keys WHERE key_id = ?");
    query.bind(1, static_cast<int64_t>(pre_key_id));
    if (!query.executeStep()) {
      return SG_ERR_INVALID_KEY_ID;
    }
    std::string key_pair = query.getColumn(0).getString();
    *record = signal_buffer_create(reinterpret_cast<const uint8_t*>(key_pair.data()), key_pair.size());
    return SG_SUCCESS;
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQLite error in load_pre_key: " << e.what() << std::endl;
    return SG_ERR_INVALID_KEY_ID;
  }

  return SG_SUCCESS;
}

int storage::pre_key_store_store_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
  auto* storage = static_cast<class storage*>(user_data);
  try {
    SQLite::Statement insert(storage->db_, "INSERT OR REPLACE INTO one_time_pre_keys (key_id, key_pair) VALUES (?, ?)");
    insert.bind(1, static_cast<int64_t>(pre_key_id));
    insert.bind(2, std::string(reinterpret_cast<char*>(record), record_len));
    insert.exec();
    return SG_SUCCESS;
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQLite error in store_pre_key: " << e.what() << std::endl;
    return SG_ERR_UNKNOWN;
  }

  return SG_SUCCESS;
}

int storage::pre_key_store_contains_pre_key(uint32_t pre_key_id, void *user_data)
{
  auto* storage = static_cast<class storage*>(user_data);
  try {
    SQLite::Statement query(storage->db_, "SELECT 1 FROM one_time_pre_keys WHERE key_id = ?");
    query.bind(1, static_cast<int64_t>(pre_key_id));
    return query.executeStep() ? 1 : 0;
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQLite error in contains_pre_key: " << e.what() << std::endl;
    return 0;
  }

  return 0;
}

int storage::pre_key_store_remove_pre_key(uint32_t pre_key_id, void *user_data)
{
  auto* storage = static_cast<class storage*>(user_data);
  try {
    SQLite::Statement del(storage->db_, "DELETE FROM one_time_pre_keys WHERE key_id = ?");
    del.bind(1, static_cast<int64_t>(pre_key_id));
    del.exec();
    return SG_SUCCESS;
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQLite error in remove_pre_key: " << e.what() << std::endl;
    return SG_ERR_UNKNOWN;
  }

  return SG_SUCCESS;
}

int storage::signed_pre_key_store_load_signed_pre_key(signal_buffer **record, uint32_t signed_pre_key_id, void *user_data)
{
  auto* storage = static_cast<class storage*>(user_data);
  try {
    SQLite::Statement query(storage->db_, "SELECT key_pair FROM signed_pre_key WHERE key_id = ?");
    query.bind(1, static_cast<int64_t>(signed_pre_key_id));
    if (!query.executeStep()) return SG_ERR_INVALID_KEY_ID;
    std::string key_pair = query.getColumn(0).getString();
    *record = signal_buffer_create(reinterpret_cast<const uint8_t*>(key_pair.data()), key_pair.size());
    return SG_SUCCESS;
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQLite error in load_signed_pre_key: " << e.what() << std::endl;
    return SG_ERR_INVALID_KEY_ID;
  }

  return SG_SUCCESS;
}

int storage::signed_pre_key_store_store_signed_pre_key(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
  auto* storage = static_cast<class storage*>(user_data);
  try {
    SQLite::Statement insert(storage->db_, "INSERT OR REPLACE INTO signed_pre_key (key_id, key_pair) VALUES (?, ?)");
    insert.bind(1, static_cast<int64_t>(signed_pre_key_id));
    insert.bind(2, std::string(reinterpret_cast<char*>(record), record_len));
    insert.exec();
    return SG_SUCCESS;
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQLite error in store_signed_pre_key: " << e.what() << std::endl;
    return SG_ERR_UNKNOWN;
  }

  return SG_SUCCESS;
}

int storage::signed_pre_key_store_contains_signed_pre_key(uint32_t signed_pre_key_id, void *user_data)
{
  auto* storage = static_cast<class storage*>(user_data);
      try {
        SQLite::Statement query(storage->db_, "SELECT 1 FROM signed_pre_key WHERE key_id = ?");
        query.bind(1, static_cast<int64_t>(signed_pre_key_id));
        return query.executeStep() ? 1 : 0;
      } catch (const SQLite::Exception& e) {
        std::cerr << "SQLite error in contains_signed_pre_key: " << e.what() << std::endl;
        return 0;
      }

  return 0;
}

int storage::session_store_load_session(signal_buffer **record, signal_buffer **user_record, const signal_protocol_address *address, void *user_data)
{
  auto* storage = static_cast<class storage*>(user_data);
  try {
    std::string recipient_id(address->name, address->name_len);
//    SQLite::Statement query(storage->db_, "SELECT session_record FROM sessions WHERE recipient_id = ?");
//    query.bind(1, recipient_id);
//    if (!query.executeStep()) {
//      std::cerr << "No session found for " << recipient_id << std::endl;
//      *record = nullptr;
//      return 0;
//    }
//    std::string session_data = query.getColumn(0).getString();
    if (const auto it = sessions_.find(recipient_id); it != sessions_.end())
    {
      auto session_data = it->second.record;
      *record = signal_buffer_create(reinterpret_cast<const uint8_t*>(session_data.data()), session_data.size());

      std::cerr << "Loading session for " << recipient_id << " (len=" << session_data.size() << "): ";
      for (size_t i = 0; i < std::min(session_data.size(), (size_t)16); ++i) {
        std::cerr << std::hex << (int)(uint8_t)session_data[i] << " ";
      }
      std::cerr << std::dec << std::endl;

      if (!*record) {
        return SG_ERR_NOMEM;
      }
      if (user_record) {
        *user_record = nullptr;
      }
      std::cerr << "Loaded session for " << recipient_id << std::endl;
      return 1; // Found session
    }
    return 0;
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQLite error in load_session: " << e.what() << std::endl;
    return SG_ERR_UNKNOWN;
  }
}

int storage::session_store_store_session(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data)
{

  auto* storage = static_cast<class storage*>(user_data);
  try {
    std::string recipient_id(address->name, address->name_len);
    std::string session_data(reinterpret_cast<char*>(record), record_len);
    std::cerr << "Storing session for " << recipient_id << " (len=" << record_len << "): ";
    for (size_t i = 0; i < std::min(record_len, (size_t)16); ++i) { // Limit for brevity
      std::cerr << std::hex << (int)record[i] << " ";
    }
    std::cerr << std::dec << std::endl;

//    SQLite::Statement insert(storage->db_, "INSERT OR REPLACE INTO sessions (recipient_id, session_record) VALUES (?, ?)");
//    insert.bind(1, recipient_id);
//    insert.bind(2, std::string(reinterpret_cast<char*>(record), record_len));
//    insert.exec();
    sessions_.insert_or_assign(recipient_id, session_t{.record = session_data});
    return SG_SUCCESS;
  } catch (const std::exception e) {
 //   std::cerr << "SQLite error in store_session: " << e.what() << std::endl;
    std::cerr << "Error in store_session: " << e.what() << std::endl;
    return SG_ERR_UNKNOWN;
  }
  return SG_SUCCESS;
}
