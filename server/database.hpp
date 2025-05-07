#pragma once

#include <SQLiteCpp/SQLiteCpp.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

using json = nlohmann::json;

struct user_key_bundle {
  std::string identity_key;
  std::string signed_pre_key;
  std::vector<std::string> one_time_pre_keys;
};

class database {
public:
  database(const std::string& db_path);
  bool register_user(const std::string& username, const user_key_bundle& key_bundle);
  user_key_bundle get_user_key_bundle(const std::string& username);
  bool create_group(const std::string& group_id, const std::string& group_name);
  bool add_user_to_group(const std::string& group_id, const std::string& username);
  std::vector<std::string> get_group_members(const std::string& group_id);
  bool store_message(const std::string& recipient, const json& message);
  std::vector<json> get_pending_messages(const std::string& username);

private:
  SQLite::Database db_;
};
