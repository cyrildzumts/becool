#include <iostream>
#include "../include/server.h"


using namespace std;

int main(int argc, char *argv[])
{
    Server server;
    server.init();
    server.start();
    return 0;
}
