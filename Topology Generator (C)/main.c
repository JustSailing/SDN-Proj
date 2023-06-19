#include "gen.h"
#include "types.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    Hosts *host = NULL;
    host = generateHosts(47, 5);
//    Hosts *host_temp = NULL;
//    host_temp = host;
//    while (host_temp != NULL) {
//        printf("name: %s, mac: %s, ip: %s, port: %s\n", host_temp->m_interfaces->m_inter->m_name,
//               host_temp->m_interfaces->m_inter->m_mac, host_temp->m_interfaces->m_inter->m_ip,
//               host_temp->m_interfaces->m_inter->m_port);
//        Commands *tp = host_temp->m_commands;
//        while (tp != NULL) {
//            printf("cmd: %s fg: %s", tp->m_command->m_command, tp->m_command->m_fg);
//            tp = tp->next_cmd;
//        }
//        host_temp = host_temp->next_host;
//    }
    //both functions below was moved to
    //deInitInterfaces(inter);
    //deInitCommands(host->m_commands);
    char *name = "Swt1";
    Switch *sw = generateSwitch(host, name);
    FILE* f = fopen(argv[1], "a");
    writeToYamlFile(f, host, sw);
//    printf("Switch => name: %s, ip: %s\n", sw->m_name, sw->m_ip);
//    Links *ln = sw->m_links;
//    while (ln != NULL) {
//        printf("inter-name: %s, mac: %s, port: %s\n", ln->m_data->m_name, ln->m_data->m_mac, ln->m_data->m_port);
//        ln = ln->next_ln;
//    }
//    Table *tb = sw->m_tables;
//    while (tb != NULL) {
//        size_t i = 0;
//        //size_t len = sizeof(char*)/sizeof(sw->m_tables->m_cmds[0]);
//        //printf("%ld\n", len);
//        size_t len = sw->m_num_hosts;
//        while(i < len) {
//            printf("%s", tb->m_cmds[i]);
//            i++;
//        }
//        tb = tb->m_next_table;
//    }
    deInitHosts(host);
    deInitSwitch(sw);
    return EXIT_SUCCESS;
}
