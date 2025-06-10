#include "client.hpp"
#include <boost/asio.hpp>
#include <iostream>

int main(int argc, char* argv[])
{
  if (argc != 4) {
    std::cerr << "Usage: " << argv[0] << " <host> <port> <username>" << std::endl;
    return 1;
  }


  if (sodium_init() < 0) {
    std::cerr << "Failed to initialize libsodium" << std::endl;
    return 1;
  }


  try
  {
    std::cout << "Creating new IO context" << std::endl;
    boost::asio::io_context io_context;

    while (true)
    {
      std::cout << "Creating new KComms Client for " << argv[3] << std::endl;

      client c(io_context, argv[1], argv[2], argv[3]);
      io_context.run();

      std::cout << "Resetting IO Context" << std::endl;
      io_context.reset();
    }
  } catch (const std::exception& e) {
    std::cerr << "Exception: " << e.what() << std::endl;
  }

  return 0;
}
