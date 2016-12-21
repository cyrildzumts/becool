#include <iostream>
#include "../include/server.h"
#include "inputargreader.h"


using namespace std;

int main(int argc, char *argv[])
{
    std::vector<std::string> args = Tools::input_arg_reader<2>(argc, argv);
    std::string ip = args.at(1);
    std::string port = args.at(2);
    if(!isAddressValid(ip.c_str()))
    {
        std::cout << "address " << ip << " is invalid." << std::endl;
        exit(EXIT_FAILURE);
    }
    Server server(ip, port);
    server.init();
    server.start();
    return 0;
}
