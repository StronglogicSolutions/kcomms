#include "client.hpp"
#include <boost/asio.hpp>
#include <iostream>

int main(int argc, char* argv[])
{
  if (sodium_init() < 0) {
    std::cerr << "Failed to initialize libsodium" << std::endl;
    return 1;
  }

        auto config = get_config();
  const auto host   = ( argc > 1 ) ? argv[1] : config["host"];
  const auto port   = ( argc > 2 ) ? argv[2] : config["port"];
  const auto user   = ( argc > 3 ) ? argv[3] : config["user"];

  try
  {
    boost::asio::io_context io_context;

    while (true)
    {
      std::cout << "Creating new KComms Client for " << user << std::endl;

      client c(io_context, host, port, user);
      io_context.run();

      std::cout << "Resetting IO Context" << std::endl;
      io_context.reset();
    }
  }
  catch (const std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << std::endl;
  }

  return 0;
}
