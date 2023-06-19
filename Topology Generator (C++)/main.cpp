#include <iostream>
#include <fstream>
#include <sstream>
#include "types.h"

// used to keep track of previous ip created
ip ip_add = "10.0.0.0";
// not sure if i need this
int index = 0;
mac mac_ = "02:00:00:00:00:00";

int main(int argc, char **argv)
{
    using namespace std;
    // program_name number_fe number_readout switches
    // TODO: The command line arguments can add number of network interfaces used by a switch or host
    // Default would be fe has 1 network interface and the switch has number of fe + number of read outs
    // TODO: also cfg is missing in the command line
    if (argc < 5 || argc > 5)
    {
        cout << "[ERROR] number of command line arguments\n"
             << "[HELP] program_name number_fe number_readout number_switches name_of_topology\n"
             << endl;
        exit(EXIT_FAILURE);
    }
    // possible failure here if command line arguments are not numbers
    auto number_fe = stoi(argv[1]);
    auto number_readouts = stoi(argv[2]);
    auto switches = stoi(argv[3]);
    auto number_of_ip = number_fe + number_readouts; // + switches; have the switch be 10.0.0.0
    auto all_ips = generateIp(number_of_ip);
    ofstream topo;
    string file = argv[4];
    file += ".yml";
    // topo.open(file, ios::app);
    auto fss = generateSwitches(switches, number_fe, number_readouts);
    generateHosts(all_ips, number_fe, number_readouts, fss, file);
    topo.close();
    return EXIT_SUCCESS;
}

std::vector<std::string> generateIp(int32_t num) noexcept
{
    using namespace std;
    vector<std::string> qu;
    for (auto it = 0; it < num; it++)
    {
        vector<std::string> vec;
        int i = 0;
        string temp = "";
        // separates each part of the ip address into 4 sections
        // helping to create new ip addresses
        while (i < ip_add.length())
        {
            if (ip_add[i] == '.')
            {
                vec.push_back(temp);
                i++;
                temp = "";
                continue;
            }
            else
            {
                temp += ip_add[i];
                i++;
                continue;
            }
        }
        vec.push_back(temp);
        if (vec.size() != 4)
        {
            cout << "[ERROR] generatingIp: vector should have a size of 4 (size: " << vec.size() << ")\n";
            for(const auto & i : vec) cout << i << endl;
            exit(EXIT_FAILURE);
        }
        i = vec.size() - 1;
        while (i >= 0)
        {
            string ip = vec[i];
            auto _ip = stoi(ip);
            if (_ip + 1 <= 255)
            {
                _ip += 1;
                vec[i] = to_string(_ip);
                break;
            }
            else
            {
                // vec[i] = "0"; // maybe its better to keep it at 10.0.0.255 and the next one is 10.0.1.255
                i--;
                continue;
            }
        }
        temp = "";
        auto check = 1;
        for (const auto &i : vec)
        {
            temp += i;
            if (check == 4)
                break;
            temp += '.';
            check++;
        }
        ip_add = temp;
        qu.push_back(temp);
    }
    return qu;
}

void generateHosts(std::vector<std::string> &qu, int32_t fe_num, int32_t rd_out, std::vector<Switch> &sw, std::string& file) noexcept
{
    using namespace std;
    ofstream fs;
    fs.open(file, ios::app);
    ostringstream ss("");
    ss << "hosts:\n";
    std::string st = ss.str();
    fs.write(st.c_str(),st.length());
    ss.str("");
    fs.flush();
    Interface iface{};
    //vector<Host> h;
    Host hs{};
    for (int i = 0; i < fe_num; i++)
    {
        string fe = "FE";
        iface.m_ip = qu[i];
        iface.m_port = "1";
        iface.m_mac = generateMac();
        fe += to_string(i + 1);
        iface.m_name = fe;
        ss << "    " << fe << ":"
          << "\n"
          << "        "
          << "interfaces:\n"
          << "            - mac: ";
          auto chk = sw[0].m_table_egress.find(fe);
          if(chk == sw[0].m_table_egress.end())
          {
            cout << "[ERROR]: Egress table did not have the host interface (FE)" << fe << endl;
            exit(EXIT_FAILURE);
          }
          ss << "\'" << chk->second.first << '\'' << "\n"
          << "              ip: " << iface.m_ip << "/24" << "\n"
          << "              port: " << iface.m_port << "\n"
          << "        programs:\n"
          << "            - cmd: " << "\"echo \'Hello from " << fe << "\'\"\n"
          << "              fg: True\n"
          << "            - cmd: " << "\"sudo route add default " << fe << "-eth1\"\n"
          << "              fg: True\n"
          << "            - cmd: " << "\"sudo arp -v -i " << fe << "-eth1" << " -s " << sw[0].m_ip << " ";
        string mac_temp;
        auto it = sw[0].m_mac_map.find(iface.m_name);
        if(it == sw[0].m_mac_map.end())
        {
            cout << "[ERROR] the switch generator was not working correctly\n";
            exit(EXIT_FAILURE);
        }
        ss << it->second << "\"\n" << "              fg: True\n";
        st = ss.str();
        fs.write(st.c_str(), st.length());
        fs.flush();
        ss.str("");
        for(int ite = 0; ite < qu.size(); ite++)
        {
            if(ite == i) continue;
            string f_e;
            if(ite + 1 > fe_num) {f_e = "ROS" + to_string(ite - fe_num + 1);}
            else { f_e = "FE" + to_string(ite + 1);}
            ss << "            - cmd: " << "\"sudo arp -v -i " << fe << "-eth1" << " -s " << qu[ite];
            auto ma = sw[0].m_table_egress.find(f_e);
            if(ma == sw[0].m_table_egress.end())
            {
                cout << "[ERROR]: Egress table did not have the host interface (FE) in arp" << f_e <<endl;
                exit(EXIT_FAILURE);
            }
            ss << " " << ma->second.first << "\"\n              fg: True\n";
        }
        hs.m_interfaces.push_back(iface);
        //h.push_back(hs);
    }
    for (int i = 0; i < rd_out; i++)
    {
        string fe = "ROS";
        iface.m_ip = qu[i+fe_num];
        iface.m_port = "1";
        iface.m_mac = generateMac();
        fe += to_string(i + 1);
        iface.m_name = fe;
        ss << "    " << fe << ":"
          << "\n"
          << "        "
          << "interfaces:\n"
          << "            - mac: ";
          auto chk = sw[0].m_table_egress.find(fe);
          if(chk == sw[0].m_table_egress.end())
          {
            cout << "[ERROR]: Egress table did not have the host interface (ReadOutServer)\n" << endl;
            exit(EXIT_FAILURE);
          }
          ss << "\'" << chk->second.first << '\'' << "\n"
          << "              ip: " << iface.m_ip << "/24" << "\n"
          << "              port: " << iface.m_port << "\n"
          << "        programs:\n"
          << "            - cmd: " << "\"echo \'Hello from " << fe << "\'\"\n"
          << "              fg: True\n"
          << "            - cmd: " << "\"sudo route add default " << fe << "-eth1\"\n"
          << "              fg: True\n"
          << "            - cmd: " << "\"sudo arp -v -i " << fe << "-eth1" << " -s " << sw[0].m_ip << " ";
        string mac_temp;
        auto it = sw[0].m_mac_map.find(iface.m_name);
        if(it == sw[0].m_mac_map.end())
        {
            cout << "[ERROR] the switch generator was not working correctly\n";
            exit(EXIT_FAILURE);
        }
        ss << it->second << "\"\n" << "              fg: True\n";
        //hs.m_interfaces.push_back(iface);
        //h.push_back(hs);
        for(int itt = 0; itt < qu.size(); itt++)
        {
            //if(itt == i) continue;
            string f_e;
            if(itt + 1 > fe_num) {f_e = "ROS" + to_string(itt - fe_num + 1);}
            else {f_e = "FE" + to_string(itt + 1);}
            if(itt + 1 > fe_num && (itt - fe_num) == i) continue;
            // cout << f_e << endl;
            ss << "            - cmd: " << "\"sudo arp -v -i " << fe << "-eth1" << " -s " << qu[itt];
            auto ma = sw[0].m_table_egress.find(f_e);
            if(ma == sw[0].m_table_egress.end())
            {
                cout << "[ERROR]: Egress table did not have the host interface (FE)\n" << endl;
                exit(EXIT_FAILURE);
            }
            ss << " " << ma->second.first << "\"\n              fg: True\n";
        }
        st = ss.str();
        fs.write(st.c_str(), st.length());
        fs.flush();
        ss.str("");
    }
    ss << "switches:\n";
    st = ss.str();
    fs.write(st.c_str(), st.length());
    fs.flush();
    ss.str("");
    int i = 0;
    for(const auto & swid : sw)
    {
        ss << "    " << swid.m_name << ":\n";
        // At the moment we will keep it fixed name for p4 file
        ss << "        " << "cfg: ../../build/BMv2/networks/Project/DUNE.json\n";
        ss << "        interfaces:\n";
        while(i < (rd_out + fe_num)) {
            ss << "            - link: " << swid.m_ifaces[i].m_name << "\n";
            //i++;
            ss << "              mac: \'";
            auto it = sw[0].m_mac_map.find(swid.m_ifaces[i].m_name);
            if (it == sw[0].m_mac_map.end()) {
                cout << "[ERROR] the switch part for host mac address did not work" << endl;
                exit(EXIT_FAILURE);
            }
            ss << it->second << '\'' << '\n';
            auto c = sw[0].m_table_egress.find(swid.m_ifaces[i].m_name);
            if (c == sw[0].m_table_egress.end()) {
                cout << "[ERROR] the switch part for host mac address in interfaces section didn't work" << endl;
                exit(EXIT_FAILURE);
            }
            ss << "              port: " << c->second.second << "\n";
            i++;
        }
        ss << "        cmds:\n" << "            #SWITCHING\n";
        for(const auto &ifac : swid.m_ifaces)
        {
            ss << "            #" << " " << ifac.m_name << "\n";
            ss << "            - table_add mac_forwarding mac_forward_set_egress ";
            auto ck = sw[0].m_table_egress.find(ifac.m_name);
            if(ck == sw[0].m_table_egress.end())
            {
                cout << "[ERROR]: getting mac addresses for table mac forwarding failed\n";
                exit(EXIT_FAILURE);
            }
            ss << ck->second.first << " => " << ck->second.second << "\n";
        }
        ss << "            #ARP\n";
        for(auto iterr = 0; iterr < qu.size(); iterr++)
        {
            string host;
            if(iterr + 1 <= fe_num)
            {
                host = "FE" + to_string(iterr+1);
            }
            else
            {
                host = "ROS" + to_string(iterr - fe_num + 1);
            }
            ss << "            #" << host << '\n';
            ss << "            - table_add next_hop_arp_lookup arp_lookup_set_addresses " << qu[iterr] << " => ";
            auto ma = sw[0].m_table_egress.find(host);
            if(ma == sw[0].m_table_egress.end())
            {
                cout << "[ERROR]: Egress table did not have the host interface (FE)" << host << endl;
                exit(EXIT_FAILURE);
            }
            ss << ma->second.first << "\n";
        }
        st = ss.str();
        fs.write(st.c_str(), st.length());
        fs.flush();
        ss.str("");
    }
    fs.flush();
    fs.close();
    // FIXME: I should do the switch first in order to have sudo arp -v -i h2-eth1 -s switch ip switch iface mac address
    // return h;
}

std::vector<Switch> generateSwitches(int32_t switches, int32_t fe_num, int32_t rd_out) noexcept
{
    using namespace std;
    Switch sw{};
    vector<Switch> vec;
    for(auto it = 0; it < switches; it++)
    {
        // ROS READ out switch
        sw.m_name = "ROSw";
        sw.m_name += to_string(it + 1);
        sw.m_ip = generateIp(1)[0];
        for(auto iter = 1; iter <= fe_num; iter++)
        {
            Interface iface{};
            string fe = "FE" + to_string(iter);
            iface.m_name = fe;
            iface.m_port = to_string(iter);
            iface.m_mac = generateMac();
            sw.m_mac_map.insert(make_pair(fe, iface.m_mac));
            sw.m_ifaces.push_back(iface);
            sw.m_table_egress.insert(make_pair(fe, pair<mac,port>(generateMac(), iface.m_port)));
            // vec.push_back(sw);
        }
        for(auto iter = 1; iter <= rd_out; iter++)
        {
            Interface iface{};
            string fe = "ROS" + to_string(iter);
            iface.m_name = fe;
            iface.m_port = to_string(iter + fe_num);
            iface.m_mac = generateMac();
            sw.m_mac_map.insert(make_pair(fe, iface.m_mac));
            sw.m_ifaces.push_back(iface);
            sw.m_table_egress.insert(make_pair(fe, pair<mac,port>(generateMac(), iface.m_port)));
            //vec.push_back(sw);
        }
        vec.push_back(sw);
    }

    return vec;
}

std::string generateMac() noexcept
{
    int i = 0;
    using namespace std;
    string temp = "";
    vector<string> vec;
    while (i < mac_.length())
    {
        if (mac_[i] == ':')
        {
            vec.push_back(temp);
            i++;
            temp = "";
            continue;
        }
        else
        {
            temp += mac_[i];
            i++;
            continue;
        }
    }
    vec.push_back(temp);
    i = vec.size() - 1;
    while(i >= 0)
    {
        string mc = vec[i];
        // cout << mc << endl;
        if(mc == "ff")
        {
            i--;
            continue;
        }
        else if(mc[1] == '9')
        {
            mc[1] = 'a';
            vec[i] = mc;
            break;
        }
        else if(mc[1] == 'f' && mc[0] == '9')
        {
            mc[0] = 'a';
            vec[i] = mc;
            break;
        }
        else if(mc[1] == 'f')
        {
            mc[0] += 1;
            vec[i] = mc;
            break;
        }
        else
        {
            mc[1] += 1;
            vec[i] = mc;
            break;
        }

    }
    temp = "";
    for(const auto &it : vec)
    {
        temp += it + ":";
    }
    mac_ = temp.substr(0,temp.length() - 1);
    cout << mac_ << endl;
    return mac_;
}