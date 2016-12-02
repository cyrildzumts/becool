BeCool is a little TCP based Client/Server chat application.
This Project is divised under 3 subprojects :
* A Common header and sources files used by both the server and the client
* A client
* A Server

See the readme of each subproject for more informations.
---------------------------------------------------------------
-- Compilation
To compile this application you need the following :
* GCC version 4.7.3+ ( C++11 must be supported)
* CMake 2.6+
* an actual Linux kernel
---------------------------------------------------------------

1- create a build directory from to the root directory:
   mkdir build
2- change to the directory you have just created.
   cd build
3- call CMake to create a Makefile and all the needed files.
   cmake ..
4- compile the application
   make
   
5- find your binary file in project_root_dir --> bin


Notice ! As of now the Server IP and port are hardcoded in common-->common.h.

if you find some bug, please let me known about it.

