#pragma once
#include <thread>
#include <string>

#ifndef _WIN32
#include <pthread.h>
#endif

std::string
get_time();

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

#ifndef _WIN32
  pthread_t   thread_id_;
#endif

};

