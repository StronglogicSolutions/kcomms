#include "storage.hpp"
#include <stdexcept>
#include <sstream>

storage::storage(const std::string& db_path)
  : db_(db_path, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE)
{
  db_.exec("CREATE TABLE IF NOT EXISTS identity_key ("
           "id INTEGER PRIMARY KEY,"
           "public_key TEXT,"
           "private_key TEXT,"
           "registration_id INTEGER)");
  db_.exec("CREATE TABLE IF NOT EXISTS signed_pre_keys ("
           "key_id INTEGER PRIMARY KEY,"
           "public_key TEXT,"
           "private_key TEXT)");
  db_.exec("CREATE TABLE IF NOT EXISTS one_time_pre_keys ("
           "key_id INTEGER PRIMARY KEY,"
           "public_key TEXT,"
           "private_key TEXT)");
  db_.exec("CREATE TABLE IF NOT EXISTS sessions ("
           "recipient TEXT PRIMARY KEY,"
           "session_data TEXT)");
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
    .store_session_func = session_store_store_session,
    .destroy_func = nullptr,
    .user_data = this
  };

  signal_protocol_store_context_set_identity_key_store(store_ctx, &identity_store);
  signal_protocol_store_context_set_pre_key_store(store_ctx, &pre_key_store);
  signal_protocol_store_context_set_signed_pre_key_store(store_ctx, &signed_pre_key_store);
  signal_protocol_store_context_set_session_store(store_ctx, &session_store);
}

user_key_bundle storage::generate_key_bundle()
{
  user_key_bundle bundle;
  // Placeholder: Generate keys using signal_protocol_key_helper_generate_identity_key_pair, etc.
  // Store in SQLite and return public keys
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
int storage::identity_key_store_get_identity_key_pair(signal_buffer** ctx, signal_buffer** keyp, void* user_data = nullptr)
{
  // Implement: Load identity key pair from SQLite
  return SG_SUCCESS;
}

int storage::identity_key_store_get_local_registration_id(void* ctx, uint32_t* idp)
{
  // Implement: Load registration ID from SQLite
  *idp = 1; // Placeholder
  return SG_SUCCESS;
}

int storage::identity_key_store_save_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
  // Implement: Save recipient's identity key
  return SG_SUCCESS;
}

int storage::identity_key_store_is_trusted_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
  // Implement: Check if identity key is trusted
  return SG_SUCCESS;
}

int storage::pre_key_store_load_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data)
{
  // Implement: Load one-time pre-key from SQLite
  return SG_SUCCESS;
}

int storage::pre_key_store_store_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
  // Implement: Store one-time pre-key in SQLite
  return SG_SUCCESS;
}

int storage::pre_key_store_contains_pre_key(uint32_t pre_key_id, void *user_data)
{
  // Implement: Check if pre-key exists
  return 0;
}

int storage::pre_key_store_remove_pre_key(uint32_t pre_key_id, void *user_data)
{
  // Implement: Remove pre-key
  return SG_SUCCESS;
}

int storage::signed_pre_key_store_load_signed_pre_key(signal_buffer **record, uint32_t signed_pre_key_id, void *user_data)
{
  // Implement: Load signed pre-key
  return SG_SUCCESS;
}

int storage::signed_pre_key_store_store_signed_pre_key(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
  // Implement: Store signed pre-key
  return SG_SUCCESS;
}

int storage::signed_pre_key_store_contains_signed_pre_key(uint32_t signed_pre_key_id, void *user_data)
{
  // Implement: Check if signed pre-key exists
  return 0;
}

int storage::session_store_load_session(signal_buffer **record, signal_buffer **user_record, const signal_protocol_address *address, void *user_data)
{
  // Implement: Load session
  return SG_SUCCESS;
}

int storage::session_store_store_session(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data)
{
  // Implement: Store session
  return SG_SUCCESS;
}
