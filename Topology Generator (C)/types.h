#ifndef TYPES_H
#define TYPES_H

#include <stddef.h>
#include <stdint-gcc.h>

typedef char *mac;
typedef char *ip;
typedef char *port;
typedef char *link;
typedef char *name;
typedef char *cmd;
typedef char *fg;
typedef char *func;

// @FIXME should be named host but would have been easily confused with Hosts
typedef struct Interface {
    name m_name;
    mac m_switch_link;
    mac m_mac;
    ip m_ip;
    ip m_switch_ip;
    port m_switch_port;
    port m_port;
} Interface;

typedef struct Interfaces {
    Interface *m_inter;
    // @INCOMPLETE prev_interface is not really used by any function other than the generation of struct Interfaces
    // The purpose of this is more for the future if I wanted to just read a topology yml file and add more tables
    // or more host, instead of regenerating everything over. Mainly for future modularity
    struct Interfaces *prev_interface;
    struct Interfaces *next_interface;
} Interfaces;

typedef struct Command {
    cmd m_command;
    fg m_fg;
} Command;

typedef struct Commands {
    Command *m_command;
    struct Commands *prev_cmd;
    struct Commands *next_cmd;
} Commands;

typedef struct Hosts {
    Interfaces *m_interfaces;
    Commands *m_commands;
    struct Hosts *next_host;
} Hosts;

typedef struct Link {
    link m_name;
    mac m_mac;
    port m_port;
} Link;

typedef struct Links {
    Link *m_data;
    // @INCOMPLETE prev_ln is not really used by any function other than the generation of struct Links
    // The purpose of this is more for the future if I wanted to just read a topology yml file and add more tables
    // or more host, instead of regenerating everything over. Mainly for future modularity
    struct Links *prev_ln;
    struct Links *next_ln;
} Links;

typedef struct Table {
    name m_name;
    func m_func_name;
    uint32_t m_num_of_cmds;
    char **m_cmds;
    struct Table *m_next_table;
} Table;

typedef struct Switch {
    size_t m_num_hosts;
    name m_name;
    ip m_ip;
    char* m_cfg;
    Links *m_links;
    Table *m_tables;
} Switch;

#endif
