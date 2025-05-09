#include "cli.hpp"
#include "client.hpp"
#include <iostream>

cli::cli(client& client_instance, const std::string& username)
  : client_(client_instance),
    username_(username),
    running_(false)
{
}

cli::~cli()
{
  stop();
}

void cli::start()
{
  if (!running_) {
    running_ = true;
    thread_ = std::thread(&cli::run, this);
  }
}

void cli::stop()
{
  if (running_) {
    running_ = false;
    if (thread_.joinable()) {
      thread_.join();
    }
  }
}

void cli::run()
{
  std::string input;
  while (running_) {
    std::cout << username_ << "> ";
    std::getline(std::cin, input);
    if (!running_) break;
    if (!input.empty()) {
      client_.send_message("group:default", input);
    }
  }
}
