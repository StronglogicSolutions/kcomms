#include "server.hpp"
#include <boost/asio.hpp>
#include <iostream>

int main()
{
  try {
    boost::asio::io_context io_context;
    server s(io_context, 12345);
    io_context.run();
  } catch (const std::exception& e) {
    std::cerr << "Exception: " << e.what() << std::endl;
  }
  return 0;
}
