cmake_minimum_required(VERSION 3.29)
project(pcap_test)

set(CMAKE_CXX_STANDARD 20)

add_executable(pcap_test main.cpp)

# libpcap 라이브러리를 직접 링크
target_link_libraries(pcap_test PRIVATE pcap)
