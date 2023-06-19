#include <vector>
#include <fstream>
#include <queue>
#include <string>
#include <unordered_map>
#include <utility>

using mac  = std::string;
using ip   = std::string;
using port = std::string;
using link = std::string;
using name = std::string;
using cmd  = std::string;
using fg   = std::string;
// using name = std::string;
/// @brief Used for structuring interfaces for switches/hosts
///        to help create a topology
/// Example:
///         interfaces:
///             - mac: '02:00:00:d8:c2:6b'
///               ip: 192.0.1.1/24
///               port: 1
struct Interface {
    /// host name 
    name m_name;
    /// found in switch part of the topology
    link m_link;
    /// mac address of the network interface
    mac  m_mac;
    /// ip address of the network interface
    ip   m_ip;
    /// port number of the network interface
    port m_port;
};

/// @brief Part of the 'programs' section of hosts/switch
/// Example:
///     programs:
///         - cmd: "echo 'Hello from h2'"
///           fg: True
struct Command {
    /// commands 
    cmd m_command;
    /// not sure what fg is but its always true
    fg  m_fg;
};

struct Host {
    std::vector<Interface> m_interfaces;
    std::vector<Command> m_commands;
};

struct Switch {
    name m_name;
    ip   m_ip;
    std::vector<Interface> m_ifaces;
    std::unordered_map<name, mac> m_mac_map;
    std::unordered_map<name, std::pair<mac, port>> m_table_egress;
};

/// @brief creates a number of ip address
/// @param  number of ip address wanted
/// @return a vector that holds all ip addresses
std::vector<std::string> generateIp(int32_t) noexcept;

/// @brief creates hosts for the topology
/// @param  vector of ip address to use
/// @return vector of hosts
void generateHosts(std::vector<std::string>&, int32_t, int32_t, std::vector<Switch>&, std::string&) noexcept;

std::string generateMac(void) noexcept;

std::vector<Switch> generateSwitches(int32_t, int32_t, int32_t) noexcept;