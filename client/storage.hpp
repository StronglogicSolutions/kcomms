#pragma once

#include <SQLiteCpp/SQLiteCpp.h>
#include <signal_protocol.h>
#include <string>
#include <vector>

struct user_key_bundle {
  std::string identity_key;
  std::string signed_pre_key;
  std::vector<std::string> one_time_pre_keys;
};

class storage {
public:
  storage(const std::string& db_path);
  ~storage();
  void initialize_signal(signal_protocol_store_context* store_ctx);
  user_key_bundle generate_key_bundle();
  void save_session(const std::string& recipient, const std::string& session_data);
  std::string load_session(const std::string& recipient);
  void save_group(const std::string& group_id, const std::string& group_name);
  std::vector<std::string> get_group_members(const std::string& group_id);

  // Signal Protocol callbacks
  static int identity_key_store_get_identity_key_pair(signal_buffer** ctx, signal_buffer** keyp, void*);
  static int identity_key_store_get_local_registration_id(void* ctx, uint32_t* idp);
  static int identity_key_store_save_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data);
  static int identity_key_store_is_trusted_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data);
  static int pre_key_store_load_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data);
  static int pre_key_store_store_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data);
  static int pre_key_store_contains_pre_key(uint32_t pre_key_id, void *user_data);
  static int pre_key_store_remove_pre_key(uint32_t pre_key_id, void *user_data);
  static int signed_pre_key_store_load_signed_pre_key(signal_buffer **record, uint32_t signed_pre_key_id, void *user_data);
  static int signed_pre_key_store_store_signed_pre_key(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data);
  static int signed_pre_key_store_contains_signed_pre_key(uint32_t signed_pre_key_id, void *user_data);
  static int session_store_load_session(signal_buffer **record, signal_buffer **user_record, const signal_protocol_address *address, void *user_data);
  static int session_store_store_session(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data);

private:
  SQLite::Database db_;
};
