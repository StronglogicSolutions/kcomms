#pragma once
#include <thread>
#include <string>

class client;  // Forward declaration

class cli {
public:
  cli(client& client_instance, const std::string& username);
  ~cli();
  void start();
  void stop();

private:
  void run();

  client&     client_;
  std::string username_;
  std::thread thread_;
  bool        running_;
};

