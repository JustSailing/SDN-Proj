#include "gen.h"
#include "types.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

// @FIXME Possibly changed this into: static Interfaces *generateInterfaces()
// Have generateHosts create each Interface individually. However we would have to change the
// struct for Interfaces and the function generateCommands OR
// @POSSIBLE leave it the same way but make it static and change host parameters to the parameters used by this function
// and have generateHosts call generateInterfaces instead of doing it in main;
// @CHANGED to static and is called by generateHosts

static char *generateMacAddress() {
    static char _mac[] = "02:00:00:00:00:00";
    char *num[6];
    // @LEAK free this
    for (size_t i = 0; i < 6; i++) num[i] = (char *) malloc(3);
    char temp[3];
    size_t it_num = 0;
    // printf("%s\n", _mac);
    // split mac address in order to get a new one
    // printf("mac: %s, size: %ld\n", _mac, strlen(_mac));
    for (size_t i = 0; i < strlen(_mac); i += 3) {
        if (_mac[i] == ':') continue;
        temp[0] = _mac[i];
        temp[1] = _mac[i + 1];
        temp[2] = '\0';
        strcpy(num[it_num], temp);
        it_num++;
    }
    // printf("size of num: %ld", sizeof(num)/sizeof(char*));
    // for (int i = 0; i < 6; i++) printf("num: %s, index: %d", num[i], i);
    // AD-HOC method of creating mac addresses
    // @ISSUE given a mac address 02:00:00:00:00:ff the next mac address would be
    // 02:00:00:00:01:ff instead of 02:00:00:00:01:00 further minimizing the total amount
    // of mac address that can be generated
    for (int i = 5; i >= 0; i--) {
        mac part = num[i];
        if (strncmp(part, "ff\0", 2) == 0) {
            continue;
        } else if (part[1] == '9') {
            part[1] = 'a';
            num[i] = part;
            break;
        } else if (part[1] == 'f' && part[0] == '9') {
            part[0] = 'a';
            num[i] = part;
            break;
        } else if (part[1] == 'f') {
            part[0] += 1;
            num[i] = part;
            break;
        } else {
            part[1] += 1;
            num[i] = part;
            break;
        }
    }
    // @INCOMPLETE maybe this should be given to the function rather than malloced within the function
    // Similar to other c programs
    char *tmp = (char *) malloc(sizeof(char) * 18);
    size_t iterator = 0;
    for (size_t i = 0; i < 6; i++) {
        char *t = num[i];
        tmp[iterator] = t[0];
        iterator++;
        tmp[iterator] = t[1];
        iterator++;
        if ((i + 1) == 6) break;
        tmp[iterator] = ':';
        iterator++;
    }
    for (size_t i = 0; i < sizeof(num) / sizeof(char *); i++) free(num[i]);
    tmp[17] = '\0';
    strcpy(_mac, tmp);

    return tmp;
}

static char *generateIpAddress() {
    static char _ip[15] = "10.0.0.0";
    char *num[4];
    for (int i = 0; i < 4; i++) {
        num[i] = (char *) malloc(4);
    }
    int iter = 0;
    int num_iter = 0;
    char temp[4];
    for (size_t i = 0; i <= strlen(_ip); i++) {
        if (_ip[i] == '.' || i == strlen(_ip)) {
            temp[iter] = '\0';
            strcpy(num[num_iter], temp);
            iter = 0;
            num_iter++;
            continue;
        }
        temp[iter] = _ip[i];
        iter++;
    }
    char *test = NULL;
    long last = strtol(num[3], &test, 10);
    if (last + 1 <= 255) {
        last++;
        if (snprintf(num[3], 4, "%ld", last) < 0) {
            printf("snprintf in generateIpAddress failed");
            exit(3);
        }
    } else {
        int it = 3;
        while (true) {
            if (it < 0) {
                printf("error in generateIpAddress. it should not be less than zero");
                exit(3);
            }
            char *temp1 = num[it];
            char *test1 = NULL;
            long check = strtol(temp1, &test1, 10);
            if (check + 1 <= 255) {
                check++;
                if (snprintf(num[it], 4, "%ld", check) < 0) {
                    printf("snprintf in generateIpAddress failed");
                    exit(3);
                }
                break;
            }
            it--;
        }
    }
    unsigned long num_of_chars = 0;
    for (size_t i = 0; i < 4; i++) {
        num_of_chars += strlen(num[i]);
    }
    num_of_chars += 4;
    char *result = (char *) malloc(sizeof(char) * num_of_chars);
    // @INFO valgrind complaint: "Conditional jump or move depends on initialized value(s)"
    memset(result, '\0', sizeof(char) * num_of_chars);
    iter = 0;
    for (size_t i = 0; i < 4; i++) {
        unsigned long len = strlen(num[i]);
        for (size_t j = 0; j < len; j++) {
            result[iter] = num[i][j];
            iter++;
        }
        if (i == 3) break;
        result[iter] = '.';
        iter++;
    }
    for (size_t i = 0; i < 4; i++) {
        free(num[i]);
    }
    // @FIXME possible seg fault. Changed _ip to have the greatest possible storage to
    // fit the largest ipv4 address
    strcpy(_ip, result);
    return result;
}

static Interfaces *generateInterfaces(uint32_t fe, uint32_t re) {
    Interfaces *head = NULL;
    Interfaces *next = NULL;
    for (size_t i = 0; i < fe; i++) {
        Interfaces *inter = (Interfaces *) malloc(sizeof(Interfaces));
        char name[5];
        if (sprintf(name, "FE%ld", (i + 1)) < 0) {
            printf("sprintf did not properly work in generateHosts in FE section\n");
            exit(3);
        }
        inter->m_inter = (Interface *) malloc(sizeof(Interface));
        inter->m_inter->m_name = (char *) malloc(strlen(name) + 1);
        strcpy(inter->m_inter->m_name, name);
        inter->m_inter->m_ip = generateIpAddress();
        inter->m_inter->m_port = "1";
        inter->m_inter->m_mac = generateMacAddress();
        inter->m_inter->m_switch_link = NULL;
        inter->m_inter->m_switch_ip = NULL;
        inter->prev_interface = NULL;
        inter->next_interface = NULL;
        if (head == NULL) {
            head = inter;
            next = inter;
        } else {
            next->next_interface = (Interfaces *) inter;
            inter->prev_interface = (Interfaces *) next;
            next = inter;
        }
    }

    for (size_t i = 0; i < re; i++) {
        Interfaces *inter = (Interfaces *) malloc(sizeof(Interfaces));
        char name[5];
        if (sprintf(name, "ROS%ld", (i + 1)) < 0) {
            printf("sprintf did not properly work in generateHosts in ROS section\n");
            exit(3);
        }
        inter->m_inter = (Interface *) malloc(sizeof(Interface));
        inter->m_inter->m_name = (char *) malloc(strlen(name) + 1);
        strcpy(inter->m_inter->m_name, name);
        inter->m_inter->m_ip = generateIpAddress();
        inter->m_inter->m_port = "1";
        inter->m_inter->m_mac = generateMacAddress();
        inter->m_inter->m_switch_link = NULL;
        inter->m_inter->m_switch_ip = NULL;
        inter->prev_interface = NULL;
        inter->next_interface = NULL;
        // this should never happen since FE should have been populated;
        if (head == NULL) {
            head = inter;
            next = inter;
        } else {
            next->next_interface = inter;
            inter->prev_interface = next;
            next = inter;
        }
    }
    Interfaces *inter = (Interfaces *) malloc(sizeof(Interfaces));
    char name[5];
    if (sprintf(name, "M%d", 1) < 0) {
        printf("sprintf did not properly work in generateHosts in ROS section\n");
        exit(3);
    }
    inter->m_inter = (Interface *) malloc(sizeof(Interface));
    inter->m_inter->m_name = (char *) malloc(strlen(name) + 1);
    strcpy(inter->m_inter->m_name, name);
    inter->m_inter->m_ip = generateIpAddress();
    inter->m_inter->m_port = "1";
    inter->m_inter->m_mac = generateMacAddress();
    inter->m_inter->m_switch_link = NULL;
    inter->m_inter->m_switch_ip = NULL;
    inter->prev_interface = NULL;
    inter->next_interface = NULL;
    // this should never happen since FE should have been populated;
    if (head == NULL) {
        head = inter;
        // next = inter;
    } else {
        next->next_interface = inter;
        inter->prev_interface = next;
        // next = inter;
    }
    return head;
}

static Commands *generateCommands(Interfaces *pInterfacesHead, Interfaces *pInterfaces) {
    Commands *c_head = NULL;
    Commands *c_next = NULL;
    Interfaces *_head = pInterfacesHead;
    while (_head != NULL) {
        if (strcmp(_head->m_inter->m_name, pInterfaces->m_inter->m_name) == 0) {
            _head = _head->next_interface;
            continue;
        }
        Commands *com = (Commands *) malloc(sizeof(Commands));
        com->next_cmd = NULL;
        com->prev_cmd = NULL;
        com->m_command = (Command *) malloc(sizeof(Command));
        com->m_command->m_fg = "        fg: True\n";
        // Not sure if I need to malloc anything might need to fix this
        char *temp = (char *) malloc(sizeof(char) * 100);
        sprintf(temp, "%6s- cmd: \"sudo arp -v %s-eth1 -s %s %s\"\n", " ", pInterfaces->m_inter->m_name,
                _head->m_inter->m_ip,
                _head->m_inter->m_mac);
        com->m_command->m_command = temp;
        if (c_head == NULL) {
            c_head = com;
            c_next = com;
            _head = _head->next_interface;
        } else {
            c_next->next_cmd = (Commands *) com;
            com->prev_cmd = (Commands *) c_next;
            c_next = com;
            _head = _head->next_interface;
        }
    }
    return c_head;
}

Hosts *generateHosts(uint32_t fe, uint32_t re) {
    Interfaces *inter = generateInterfaces(fe, re);
    Interfaces *inter_head = NULL;
    inter_head = inter;
    Interfaces *inter_iter = NULL;
    inter_iter = inter;
    Hosts *head = NULL;
    Hosts *next = NULL;
    while (inter_iter != NULL) {
        Hosts *hos = NULL;
        hos = (Hosts *) malloc(sizeof(Hosts));
        hos->m_interfaces = NULL;
        hos->m_commands = NULL;
        hos->next_host = NULL;
        hos->m_interfaces = inter_iter;
        hos->m_commands = generateCommands(inter_head, inter_iter);
        if (head == NULL) {
            head = hos;
            next = hos;
        } else {
            next->next_host = hos;
            next = hos;
        }
        inter_iter = inter_iter->next_interface;
        inter_head = inter;
    }
    return head;
}

static void deInitCommands(Commands *pCommands) {
    while (pCommands != NULL) {
        if (pCommands->prev_cmd == NULL && pCommands->next_cmd == NULL) {
            free(pCommands->m_command->m_command);
            free(pCommands->m_command);
            free(pCommands);
            break;
        }

        Commands *temp = (Commands *) pCommands->prev_cmd;
        if (temp == NULL) {
            pCommands = pCommands->next_cmd;
            continue;
        }
        free(temp->m_command->m_command);
        free(temp->m_command);
        free(temp);
        if (pCommands->next_cmd == NULL) {
            free(pCommands->m_command->m_command);
            free(pCommands->m_command);
            free(pCommands);
            break;
        }
        pCommands = pCommands->next_cmd;
    }
}

static void generateMacForwardingTable(Switch *ptrSwitch, Hosts *ptrHost) {
    Interfaces *ptrHead = ptrHost->m_interfaces;
    // Table *ptrTb = ptrSwitch->m_tables;
    // while (ptrTb->m_next_table != NULL) ptrTb = ptrTb->m_next_table;
    Table *ptrTb = (Table *) malloc(sizeof(Table));
    ptrTb->m_next_table = NULL;
    ptrTb->m_func_name = NULL;
    ptrTb->m_name = NULL;
    ptrTb->m_cmds = NULL;
    char *name = "mac_forwarding ";
    char *fun = "mac_forward_set_egress ";
    char *arrow = " => ";
    char *tb = "      - table_add ";
    ptrTb->m_func_name = (char *) malloc(strlen(fun) + 1);
    strcpy(ptrTb->m_func_name, fun);
    ptrTb->m_name = (char *) malloc(strlen(name) + 1);
    strcpy(ptrTb->m_name, name);
    ptrTb->m_cmds = (char **) malloc(sizeof(char *));
    size_t index = 0;
    size_t check = 1;
    while (ptrHead != NULL) {
        if (check == 1) {
            size_t len = strlen(tb) + strlen(name) + strlen(fun) + strlen(ptrHead->m_inter->m_mac) + strlen(arrow) +
                         strlen(ptrHead->m_inter->m_switch_port) + 2;
            ptrTb->m_cmds[index] = (char *) malloc(len);
            sprintf(ptrTb->m_cmds[index], "%s%s%s%s%s%s\n", tb, name, fun, ptrHead->m_inter->m_mac, arrow,
                    ptrHead->m_inter->m_switch_port);
            index += 1;
            check += 1;
            ptrHead = ptrHead->next_interface;
        } else {
            char **temp = (char **) realloc(ptrTb->m_cmds, sizeof(char *) * check);
            if (temp == NULL) {
                printf("ERROR: reallocation failed in generate_mac addresses");
                // @Leak should deInit switch and hosts here but not sure if we should exit or just continue
                exit(3);
            }
            ptrTb->m_cmds = temp;
            size_t len = strlen(tb) + strlen(name) + strlen(fun) + strlen(ptrHead->m_inter->m_mac) + strlen(arrow) +
                         strlen(ptrHead->m_inter->m_switch_port) + 2;
            ptrTb->m_cmds[index] = (char *) malloc(len);
            sprintf(ptrTb->m_cmds[index], "%s%s%s%s%s%s\n", tb, name, fun, ptrHead->m_inter->m_mac, arrow,
                    ptrHead->m_inter->m_switch_port);
            index += 1;
            check += 1;
            ptrHead = ptrHead->next_interface;
        }

    }
    ptrTb->m_num_of_cmds = index;
    if (ptrSwitch->m_tables == NULL) {
        ptrSwitch->m_tables = ptrTb;
    } else {
        Table *pTable = ptrSwitch->m_tables;
        while (pTable->m_next_table != NULL) {
            pTable = pTable->m_next_table;
        }
        pTable->m_next_table = ptrTb;
    }
}

static void generateIpForwardingTable(Switch *s, Hosts *h) {
    Table *ptrTb = (Table *) malloc(sizeof(Table));
    ptrTb->m_next_table = NULL;
    ptrTb->m_func_name = NULL;
    ptrTb->m_name = NULL;
    ptrTb->m_cmds = NULL;
    char *name = "next_hop_arp_lookup ";
    char *fun = "arp_lookup_set_addresses ";
    char *arrow = " => ";
    char *tb = "      - table_add ";
    ptrTb->m_func_name = (char *) malloc(strlen(fun) + 1);
    strcpy(ptrTb->m_func_name, fun);
    ptrTb->m_name = (char *) malloc(strlen(name) + 1);
    strcpy(ptrTb->m_name, name);
    ptrTb->m_cmds = (char **) malloc(sizeof(char *));
    Hosts *temp = h;
    size_t index = 0;
    size_t check = 1;
    while(temp != NULL) {
        if (index == 0) {
            size_t len = strlen(tb) + strlen(name) + strlen(fun) + strlen(temp->m_interfaces->m_inter->m_ip) + strlen(arrow) +
                         strlen(temp->m_interfaces->m_inter->m_mac) + 2;
            ptrTb->m_cmds[index] = (char *) malloc(len);
            sprintf(ptrTb->m_cmds[index], "%s%s%s%s%s%s\n", tb, name, fun, temp->m_interfaces->m_inter->m_ip, arrow,
                    temp->m_interfaces->m_inter->m_mac);
            index += 1;
            check += 1;
            temp = temp->next_host;
        }
        else {
            char **tmp = (char **) realloc(ptrTb->m_cmds, sizeof(char *) * check);
            if (tmp == NULL) {
                printf("ERROR: reallocation failed in generate_mac addresses");
                // @Leak should deInit switch and hosts here but not sure if we should exit or just continue
                exit(3);
            }
            ptrTb->m_cmds = tmp;
            size_t len = strlen(tb) + strlen(name) + strlen(fun) + strlen(temp->m_interfaces->m_inter->m_ip) + strlen(arrow) +
                         strlen(temp->m_interfaces->m_inter->m_mac) + 2;
            ptrTb->m_cmds[index] = (char *) malloc(len);
            sprintf(ptrTb->m_cmds[index], "%s%s%s%s%s%s\n", tb, name, fun, temp->m_interfaces->m_inter->m_ip, arrow,
                    temp->m_interfaces->m_inter->m_mac);
            index += 1;
            check += 1;
            temp = temp->next_host;
        }
    }
    ptrTb->m_num_of_cmds = index;
    if (s->m_tables == NULL) {
        s->m_tables = ptrTb;
    } else {
        Table *pTable = s->m_tables;
        while (pTable->m_next_table != NULL) {
            pTable = pTable->m_next_table;
        }
        pTable->m_next_table = ptrTb;
    }
}

Switch *generateSwitch(Hosts *pHosts, char *name) {
    Switch *pSwitch = NULL;
    int port_num = 1;
    pSwitch = (Switch *) malloc(sizeof(Switch));
    pSwitch->m_tables = NULL;
    pSwitch->m_ip = generateIpAddress();
    pSwitch->m_name = (char *) malloc(strlen(name) + 1);
    // Links *ln = NULL;
    // ln = (Links *) malloc(sizeof(Links));
    strcpy(pSwitch->m_name, name);
    Links *head = NULL;
    Links *next = NULL;
    Hosts *temp = pHosts;
    size_t num_of_hosts = 0;
    while (temp != NULL) {
        Links *h_inter = NULL;
        h_inter = (Links *) malloc(sizeof(Links));
        h_inter->next_ln = NULL;
        h_inter->prev_ln = NULL;
        // @LEAK
        // @FIXED
        h_inter->m_data = NULL;
        h_inter->m_data = (Link *) malloc(sizeof(Link));
        h_inter->m_data->m_name = NULL;
        h_inter->m_data->m_name = (char *) malloc(strlen(temp->m_interfaces->m_inter->m_name) + 1);
        memset(h_inter->m_data->m_name, '\0', strlen(temp->m_interfaces->m_inter->m_name) + 1);
        strcpy(h_inter->m_data->m_name, temp->m_interfaces->m_inter->m_name);
        h_inter->m_data->m_mac = generateMacAddress();
        char *tmp = (char *) malloc(sizeof(char) * 5);
        memset(tmp, '\0', 5);
        sprintf(tmp, "%d", port_num);
        temp->m_interfaces->m_inter->m_switch_port = (char *) malloc(sizeof(char) * 5);
        memset(temp->m_interfaces->m_inter->m_switch_port, '\0', 5);
        strcpy(temp->m_interfaces->m_inter->m_switch_port, tmp);
        port_num++;
        h_inter->m_data->m_port = tmp;
        // @FIXME may be a segmentation fault if pSwitch lifetime is less than pHosts
        // may cause problems
        // @POSSIBLE malloc m_switch_ip and m_switch_link so freeing each one in any combination would not lead to an issue
        // @FIXED
        temp->m_interfaces->m_inter->m_switch_ip = NULL; // Not necessary handled in generateHosts
        temp->m_interfaces->m_inter->m_switch_link = NULL; // Not necessary handled in generateHosts
        temp->m_interfaces->m_inter->m_switch_ip = (char *) malloc(strlen(pSwitch->m_ip) + 1);
        temp->m_interfaces->m_inter->m_switch_link = (char *) malloc(strlen(h_inter->m_data->m_mac) + 1);
        memset(temp->m_interfaces->m_inter->m_switch_link, '\0', strlen(h_inter->m_data->m_mac) + 1);
        memset(temp->m_interfaces->m_inter->m_switch_ip, '\0', strlen(pSwitch->m_ip) + 1);
        strcpy(temp->m_interfaces->m_inter->m_switch_ip, pSwitch->m_ip);
        strcpy(temp->m_interfaces->m_inter->m_switch_link, h_inter->m_data->m_mac);
        if (head == NULL) {
            head = h_inter;
            next = h_inter;
            temp = temp->next_host;
            num_of_hosts++;
            continue;
        } else {
            next->next_ln = h_inter;
            h_inter->prev_ln = next;
            next = h_inter;
            temp = temp->next_host;
            num_of_hosts++;
        }
    }
    pSwitch->m_links = head;
    pSwitch->m_num_hosts = num_of_hosts;
    // Table *tb = pSwitch->m_tables;
    // temp = pHosts;
    generateMacForwardingTable(pSwitch, pHosts);
    generateIpForwardingTable(pSwitch, pHosts);

    return pSwitch;
}

static void writeHostToYamlFile(FILE *f, Hosts *h) {
    Hosts *t = h;
    while (t != NULL) {
        fprintf(f, "  %s:\n    interfaces:\n      - mac: \'%s\'\n        ip: %s\n        port: %s\n    programs:\n",
                t->m_interfaces->m_inter->m_name, t->m_interfaces->m_inter->m_mac, t->m_interfaces->m_inter->m_ip,
                t->m_interfaces->m_inter->m_port);
        Commands *c = t->m_commands;
        fprintf(f, "      - cmd: \"sudo route add default %s-eth1\"\n        fg: True\n",
                t->m_interfaces->m_inter->m_name);
        while (c != NULL) {
            fprintf(f, "%s%s", c->m_command->m_command, c->m_command->m_fg);
            c = c->next_cmd;
        }
        t = t->next_host;
    }
}

static void writeSwitchToYamlFile(FILE *f, Switch *s) {
    Switch *sw = s;
    fprintf(f, "switches:\n  %s:\n    cfg: ../../build/BMv2/networks/Project/DUNE.json\n    interfaces:\n", s->m_name);
    Links *ln = sw->m_links;
    while (ln != NULL) {
        fprintf(f, "      - link: %s\n        mac: \'%s\'\n        port: %s\n", ln->m_data->m_name, ln->m_data->m_mac,
                ln->m_data->m_port);
        ln = ln->next_ln;
    }
    Table *tb = sw->m_tables;
    fprintf(f, "    cmds:\n");
    while (tb != NULL) {
        size_t i = 0;
        while (i < tb->m_num_of_cmds) {
            fprintf(f, "%s", tb->m_cmds[i]);
            i++;
        }
        tb = tb->m_next_table;
    }

}

void writeToYamlFile(FILE *f, Hosts *h, Switch *s) {
    fprintf(f, "hosts:\n");
    writeHostToYamlFile(f, h);
    writeSwitchToYamlFile(f, s);
}

void deInitHosts(Hosts *pHosts) {
    while (pHosts != NULL) {
        Hosts *temp = pHosts->next_host;
        deInitCommands(pHosts->m_commands);
        // @FIXME Maybe its better to release the memory of Commands* in this function
        // as well as interfaces; however there would be a need to change the definition of deInitInterfaces
        // deInitInterfaces(pHosts->m_interfaces);
        // @FIXED
        free(pHosts->m_interfaces->m_inter->m_name);
        free(pHosts->m_interfaces->m_inter->m_mac);
        free(pHosts->m_interfaces->m_inter->m_ip);
        free(pHosts->m_interfaces->m_inter->m_switch_ip);
        free(pHosts->m_interfaces->m_inter->m_switch_link);
        free(pHosts->m_interfaces->m_inter->m_switch_port);
        free(pHosts->m_interfaces->m_inter);
        free(pHosts->m_interfaces);
        free(pHosts);
        pHosts = temp;
    }
}

void deInitSwitch(Switch *pSwitch) {
    free(pSwitch->m_name);
    free(pSwitch->m_ip);
    Links *temp = pSwitch->m_links;
    while (temp != NULL) {
        Links *tp = temp->next_ln;
        free(temp->m_data->m_name);
        free(temp->m_data->m_mac);
        free(temp->m_data->m_port);
        free(temp->m_data);
        free(temp);
        temp = tp;
    }
    Table *tb = pSwitch->m_tables;
    free(tb->m_name);
    free(tb->m_func_name);
    size_t i = 0;
    while (i < pSwitch->m_num_hosts) {
        free(tb->m_cmds[i]);
        i++;
    }
    free(tb->m_cmds);
    free(tb);
    free(pSwitch);
}


