#include "cli.hpp"
#include "client.hpp"
#include <iostream>
#include <iomanip>
#include <ctime>

std::string
get_time()
{
  const auto         now  = std::time(nullptr);
  const std::tm*     time = std::localtime(&now);
  std::ostringstream oss;
  oss << std::put_time(time, "%Y/%m/%d %H:%M:%S");
  return oss.str();
}

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
  if (!running_)
  {
    running_ = true;
    thread_ = std::thread(&cli::run, this);
  }
}

void cli::stop()
{
  if (running_)
  {
    running_ = false;
    if (thread_.joinable())
      thread_.join();
  }
}

void cli::run()
{
  std::string input;
  while (running_)
  {
    std::cout << get_time() << " - " << username_ << "> ";
    std::getline(std::cin, input);
    if (!running_)
      break;

    if (!input.empty())
      client_.send_message("group:default", input);
  }
}
