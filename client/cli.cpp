#include "cli.hpp"
#include "client.hpp"
#include <iostream>
#include <iomanip>
#include <ctime>

#ifndef _WIN32
#include <signal.h>
#endif

//-----------------------------
//-----------------------------
std::string
get_time()
{
  const auto         now  = std::time(nullptr);
  const std::tm*     time = std::localtime(&now);
  std::ostringstream oss;
  oss << std::put_time(time, "%Y/%m/%d %H:%M:%S");
  return oss.str();
}
//-----------------------------
//-----------------------------
cli::cli(client& client_instance, const std::string& username)
: client_(client_instance),
  username_(username),
  running_(false)
{
  std::cin.clear();
}
//-----------------------------
cli::~cli()
{
  stop();

  if (thread_.joinable())
    thread_.join();
}
//-----------------------------
void cli::start()
{
  if (!running_)
  {
    running_ = true;
    thread_  = std::thread(&cli::run, this);
  }
#ifndef _WIN32
  thread_id_ = thread_.native_handle();
  client_.set_thread_id(&thread_id_);
#endif
}
//-----------------------------
void cli::stop()
{
  running_ = false;
}
//-----------------------------
void cli::run()
{
#ifndef _WIN32
  struct sigaction sa;
  sa.sa_handler = [](int) {}; // NOOP
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGUSR1, &sa, nullptr);

  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  pthread_sigmask(SIG_UNBLOCK, &set, nullptr);
#endif

  std::string input;
  while (running_)
  {
    if (!running_)
      break;

    std::cout << get_time() << " - " << username_ << "> ";
    std::getline(std::cin, input);

    if (!input.empty())
      client_.send_message(input);
  }
}

