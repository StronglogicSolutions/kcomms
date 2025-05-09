#include "database.hpp"
#include <iostream>

database::database(const std::string& db_path)
  : db_(db_path, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE)
{
  db_.exec("CREATE TABLE IF NOT EXISTS users ("
           "username TEXT PRIMARY KEY,"
           "identity_key TEXT,"
           "signed_pre_key TEXT)");
  db_.exec("CREATE TABLE IF NOT EXISTS one_time_pre_keys ("
           "username TEXT,"
           "pre_key TEXT,"
           "FOREIGN KEY(username) REFERENCES users(username))");
  db_.exec("CREATE TABLE IF NOT EXISTS groups ("
           "group_id TEXT PRIMARY KEY,"
           "group_name TEXT)");
  db_.exec("CREATE TABLE IF NOT EXISTS group_members ("
           "group_id TEXT,"
           "username TEXT,"
           "FOREIGN KEY(group_id) REFERENCES groups(group_id),"
           "FOREIGN KEY(username) REFERENCES users(username))");
  db_.exec("CREATE TABLE IF NOT EXISTS messages ("
           "id INTEGER PRIMARY KEY AUTOINCREMENT,"
           "recipient TEXT,"
           "message TEXT)");
}

bool database::register_user(const std::string& username, const user_key_bundle& key_bundle)
{
  try {
    SQLite::Transaction transaction(db_);
    SQLite::Statement insert_user(db_, "INSERT INTO users (username, identity_key, signed_pre_key) VALUES (?, ?, ?)");
    insert_user.bind(1, username);
    insert_user.bind(2, key_bundle.identity_key);
    insert_user.bind(3, key_bundle.signed_pre_key);
    insert_user.exec();

    for (const auto& pre_key : key_bundle.one_time_pre_keys) {
      SQLite::Statement insert_pre_key(db_, "INSERT INTO one_time_pre_keys (username, pre_key) VALUES (?, ?)");
      insert_pre_key.bind(1, username);
      insert_pre_key.bind(2, pre_key);
      insert_pre_key.exec();
    }

    transaction.commit();
    return true;
  } catch (const SQLite::Exception& e) {
    std::cerr << "SQL Exception: " << e.what() << std::endl;
    return false;
  }
}

user_key_bundle database::get_user_key_bundle(const std::string& username)
{
  user_key_bundle bundle;
  SQLite::Statement query_user(db_, "SELECT identity_key, signed_pre_key FROM users WHERE username = ?");
  query_user.bind(1, username);
  if (query_user.executeStep()) {
    bundle.identity_key = query_user.getColumn(0).getString();
    bundle.signed_pre_key = query_user.getColumn(1).getString();
  }

  SQLite::Statement query_pre_keys(db_, "SELECT pre_key FROM one_time_pre_keys WHERE username = ?");
  query_pre_keys.bind(1, username);
  while (query_pre_keys.executeStep()) {
    bundle.one_time_pre_keys.push_back(query_pre_keys.getColumn(0).getString());
  }

  return bundle;
}

bool database::create_group(const std::string& group_id, const std::string& group_name)
{
  try {
    SQLite::Statement insert_group(db_, "INSERT INTO groups (group_id, group_name) VALUES (?, ?)");
    insert_group.bind(1, group_id);
    insert_group.bind(2, group_name);
    insert_group.exec();
    return true;
  } catch (const SQLite::Exception& e) {
    return false;
  }
}

bool database::add_user_to_group(const std::string& group_id, const std::string& username)
{
  try {
    SQLite::Statement insert_member(db_, "INSERT INTO group_members (group_id, username) VALUES (?, ?)");
    insert_member.bind(1, group_id);
    insert_member.bind(2, username);
    insert_member.exec();
    return true;
  } catch (const SQLite::Exception& e) {
    return false;
  }
}

std::vector<std::string> database::get_group_members(const std::string& group_id)
{
  std::vector<std::string> members;
  SQLite::Statement query_members(db_, "SELECT username FROM group_members WHERE group_id = ?");
  query_members.bind(1, group_id);
  while (query_members.executeStep()) {
    members.push_back(query_members.getColumn(0).getString());
  }
  return members;
}

bool database::store_message(const std::string& recipient, const json& message)
{
  try {
    SQLite::Statement insert_message(db_, "INSERT INTO messages (recipient, message) VALUES (?, ?)");
    insert_message.bind(1, recipient);
    insert_message.bind(2, message.dump());
    insert_message.exec();
    return true;
  } catch (const SQLite::Exception& e) {
    return false;
  }
}

std::vector<json> database::get_pending_messages(const std::string& username)
{
  std::vector<json> messages;
  SQLite::Statement query_messages(db_, "SELECT message FROM messages WHERE recipient = ?");
  query_messages.bind(1, username);
  while (query_messages.executeStep()) {
    messages.push_back(json::parse(query_messages.getColumn(0).getString()));
  }
  SQLite::Statement delete_messages(db_, "DELETE FROM messages WHERE recipient = ?");
  delete_messages.bind(1, username);
  delete_messages.exec();
  return messages;
}
