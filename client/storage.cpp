#include "storage.hpp"
#include <iostream>
#include "key_helper.h"
#include "signal_protocol.h"
#include "curve.h"

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

storage::storage(const std::string& db_path)
  : db_(db_path, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE)
{
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
//  db_.exec("CREATE TABLE IF NOT EXISTS identity_key ("
//           "id INTEGER PRIMARY KEY,"
//           "public_key TEXT,"
//           "private_key TEXT,"
//           "registration_id INTEGER)");
//  db_.exec("CREATE TABLE IF NOT EXISTS signed_pre_keys ("
//           "key_id INTEGER PRIMARY KEY,"
//           "public_key TEXT,"
//           "private_key TEXT)");
//  db_.exec("CREATE TABLE IF NOT EXISTS one_time_pre_keys ("
//           "key_id INTEGER PRIMARY KEY,"
//           "public_key TEXT,"
//           "private_key TEXT)");
//  db_.exec("CREATE TABLE IF NOT EXISTS sessions ("
//           "recipient TEXT PRIMARY KEY,"
//           "session_data TEXT)");
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
  user_key_bundle bundle;

  // Generate registration ID
  uint32_t registration_id = 0;
  if (signal_protocol_key_helper_generate_registration_id(&registration_id, 0, global_context) != SG_SUCCESS) {
    throw std::runtime_error("Failed to generate registration ID");
  }

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
  if (signal_protocol_key_helper_generate_signed_pre_key(&signed_pre_key, identity_key_pair, signed_pre_key_id, time(nullptr), global_context) != SG_SUCCESS) {
    SIGNAL_UNREF(identity_key_pair);
    throw std::runtime_error("Failed to generate signed pre-key");
  }
  signal_buffer* signed_pre_key_buf = nullptr;
  if (session_signed_pre_key_serialize(&signed_pre_key_buf, signed_pre_key) != SG_SUCCESS) {
    SIGNAL_UNREF(signed_pre_key);
    SIGNAL_UNREF(identity_key_pair);
    throw std::runtime_error("Failed to serialize signed pre-key");
  }
  bundle.signed_pre_key = base64_encode(signal_buffer_data(signed_pre_key_buf), signal_buffer_len(signed_pre_key_buf));
  try {
    SQLite::Statement insert_signed(db_, "INSERT INTO signed_pre_key (key_id, key_pair) VALUES (?, ?)");
    insert_signed.bind(1, static_cast<int64_t>(signed_pre_key_id));
    insert_signed.bind(2, std::string(reinterpret_cast<char*>(signal_buffer_data(signed_pre_key_buf)), signal_buffer_len(signed_pre_key_buf)));
    insert_signed.exec();
  } catch (const SQLite::Exception& e) {
    signal_buffer_free(signed_pre_key_buf);
    SIGNAL_UNREF(signed_pre_key);
    SIGNAL_UNREF(identity_key_pair);
    throw std::runtime_error("SQLite error in storing signed pre-key: " + std::string(e.what()));
  }
  signal_buffer_free(signed_pre_key_buf);
  signed_pre_key_buf = nullptr;
  SIGNAL_UNREF(signed_pre_key);
  signed_pre_key = nullptr;

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
    try {
      SQLite::Statement insert_pre(db_, "INSERT INTO one_time_pre_keys (key_id, key_pair) VALUES (?, ?)");
      insert_pre.bind(1, static_cast<int64_t>(pre_key_id));
      insert_pre.bind(2, std::string(reinterpret_cast<char*>(signal_buffer_data(pre_key_buf)), signal_buffer_len(pre_key_buf)));
      insert_pre.exec();
    } catch (const SQLite::Exception& e) {
      signal_buffer_free(pre_key_buf);
      signal_protocol_key_helper_key_list_free(pre_keys_head);
      SIGNAL_UNREF(identity_key_pair);
      throw std::runtime_error("SQLite error in storing one-time pre-key: " + std::string(e.what()));
    }
    signal_buffer_free(pre_key_buf);
    pre_key_buf = nullptr;
    node = signal_protocol_key_helper_key_list_next(node);
  }

  // Cleanup
  signal_protocol_key_helper_key_list_free(pre_keys_head);
  pre_keys_head = nullptr;
  SIGNAL_UNREF(identity_key_pair);
  identity_key_pair = nullptr;

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
int storage::identity_key_store_get_identity_key_pair(signal_buffer** ctx, signal_buffer** keyp, void* user_data)
{
  auto* storage = static_cast<class storage*>(user_data);
  try {
    SQLite::Statement query(storage->db_, "SELECT key_pair FROM identity_key LIMIT 1");
    if (!query.executeStep()) {
      return SG_ERR_UNKNOWN;
    }
    std::string key_pair = query.getColumn(0).getString();
    *keyp = signal_buffer_create(reinterpret_cast<const uint8_t*>(key_pair.data()), key_pair.size());
    *ctx = nullptr; // Unused context
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
      return SG_SUCCESS; // New key, trust by default
    }
    std::string stored_key = query.getColumn(0).getString();
    if (stored_key == std::string(reinterpret_cast<char*>(key_data), key_len)) {
      return SG_SUCCESS;
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
    SQLite::Statement query(storage->db_, "SELECT session_record FROM sessions WHERE recipient_id = ?");
    query.bind(1, recipient_id);
    if (!query.executeStep()) return SG_ERR_INVALID_KEY_ID;
    std::string session_record = query.getColumn(0).getString();
    *record = signal_buffer_create(reinterpret_cast<const uint8_t*>(session_record.data()), session_record.size());
    return SG_SUCCESS;
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQLite error in load_session: " << e.what() << std::endl;
    return SG_ERR_INVALID_KEY_ID;
  }
  return SG_SUCCESS;
}

int storage::session_store_store_session(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data)
{
  auto* storage = static_cast<class storage*>(user_data);
  try {
    std::string recipient_id(address->name, address->name_len);
    SQLite::Statement insert(storage->db_, "INSERT OR REPLACE INTO sessions (recipient_id, session_record) VALUES (?, ?)");
    insert.bind(1, recipient_id);
    insert.bind(2, std::string(reinterpret_cast<char*>(record), record_len));
    insert.exec();
    return SG_SUCCESS;
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQLite error in store_session: " << e.what() << std::endl;
    return SG_ERR_UNKNOWN;
  }
  return SG_SUCCESS;
}
