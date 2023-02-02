#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <string>
#include <optional>
#include <fstream>
#include <iostream>
#include <iomanip>

DWORD g_process_id;
HANDLE g_handle;
uintptr_t g_base;
uintptr_t g_size;
std::unique_ptr<char[]> g_data;

uintptr_t g_register_native = 0x15E4230;
uintptr_t g_register_native_2 = 0x15E3298;
uintptr_t g_system = 0x15E3F98;
uintptr_t g_namespaces_start = 0xA4BD67;
uintptr_t g_namespaces_end = 0xA4C010;
std::vector<uintptr_t> g_namespaces;

std::vector<std::vector<uintptr_t>> g_dump_hashes;

std::vector<uintptr_t> get_hashes(uintptr_t index)
{
    std::vector<uintptr_t> result;
    while (true)
    {
        //std::cout << "Index: " << std::hex << std::uppercase << index << std::dec << std::nouppercase << "\n";
        if (g_data.get()[index] == '\xC2' && g_data.get()[index + 1] == '\x00' && g_data.get()[index + 2] == '\x00') // nullsub_2
        {
            return result;
        }
        if (index == g_register_native_2) // namespace system end
        {
            return result;
        }
        if ((g_data.get()[index] == '\x48' && g_data.get()[index + 1] == '\x8D' && g_data.get()[index + 2] == '\x2D') && (index + *(int*)(g_data.get() + index + 3) + 7 == g_register_native)) // namespaces end
        {
            return result;
        }
        if ((g_data.get()[index] == '\x48' && g_data.get()[index + 1] == '\xBA') || (g_data.get()[index] == '\x48' && g_data.get()[index + 1] == '\xB9')) // Found hash
        {
            result.push_back(*(uintptr_t*)(g_data.get() + index + 2));
            index += 10;
            continue;
        }
        if (g_data.get()[index] == '\xBA') // Found hash
        {
            result.push_back(*(uint32_t*)(g_data.get() + index + 1));
            std::cout << "BA found " << std::hex << std::uppercase << index << " " << (uintptr_t) * (uint32_t*)(g_data.get() + index + 1) << std::dec << std::nouppercase << "\n";
            index += 5;
            continue;
        }
        if (g_data.get()[index] == '\xE8')
        {
            index += 5;
            continue;
        }
        if (g_data.get()[index] == '\xE9')
        {
            index += *(int*)(g_data.get() + index + 1) + 5;
            continue;
        }
        if (g_data.get()[index] == '\x48' && g_data.get()[index + 1] == '\x8D' && g_data.get()[index + 2] == '\x15' ||
            g_data.get()[index] == '\x4C' && g_data.get()[index + 1] == '\x8D' && g_data.get()[index + 2] == '\x05')
        {
            index += 7;
            continue;
        }
        index++;
    }
}

void init_namespaces()
{
    for (uintptr_t i = g_namespaces_start; i < g_namespaces_end; i++)
    {
        if (g_data.get()[i] == '\x48' && g_data.get()[i + 1] == '\x8D' && g_data.get()[i + 2] == '\x05')
        {
            g_namespaces.push_back(i + *(int*)(g_data.get() + i + 3) + 7);
            i += 7;
        }
    }
}

int main()
{
    GetWindowThreadProcessId(FindWindowA("grcWindow", nullptr), &g_process_id);
    g_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, g_process_id);

    HMODULE hMods[1024];
    DWORD cbNeeded;
    EnumProcessModules(g_handle, hMods, sizeof(hMods), &cbNeeded);
    MODULEINFO info;
    GetModuleInformation(g_handle, hMods[0], &info, sizeof(info));
    g_base = (intptr_t)info.lpBaseOfDll;
    g_size = info.SizeOfImage;
    g_data = std::make_unique<char[]>(g_size);
    ReadProcessMemory(g_handle, (LPCVOID)g_base, g_data.get(), g_size, 0);

    std::cout << "Base: " << std::hex << std::uppercase << g_base << std::dec << std::nouppercase << "\n";
    std::cout << "Size: " << std::hex << std::uppercase << g_size << std::dec << std::nouppercase << "\n";

    std::cout << "\n";

    std::cout << "Init namespaces\n";
    init_namespaces();
    //for (int i = 0; i < g_namespaces.size(); i++)
    //{
    //    std::cout << std::hex << std::uppercase << g_namespaces[i] << std::dec << std::nouppercase << "\n";
    //}
    std::cout << "Found " << g_namespaces.size() << " namespaces\n";

    std::cout << "\n";

    std::cout << "getting namespace system\n";
    g_dump_hashes.push_back(get_hashes(g_system));
    for (int i = 0; i < g_namespaces.size(); i++)
    {
        std::cout << "getting namespace " << i << "\n";
        g_dump_hashes.push_back(get_hashes(g_namespaces[i]));
    }

    std::cout << "\n";

    size_t total = 0;
    for (int i = 0; i < g_dump_hashes.size(); i++)
    {
        total += g_dump_hashes[i].size();
        std::cout << "namespace " << i << ": " << g_dump_hashes[i].size() << "\n";
    }
    std::cout << "total: " << total << "\n";

    std::cout << "\n";

    std::ofstream o("output.txt");
    for (int i = 0; i < g_dump_hashes.size(); i++)
    {
        o << "namespace " << i << ":\n";
        o << "{\n";
        for (int j = 0; j < g_dump_hashes[i].size(); j++)
        {
            o << "    " << "0x" << std::setw(16) << std::setfill('0') << std::hex << std::uppercase << g_dump_hashes[i][j] << std::dec << std::nouppercase << "\n";
        }
        o << "}\n";
    }
    o << "\n";
    for (int i = 0; i < g_dump_hashes.size(); i++)
    {
        o << "namespace " << i << ": " << g_dump_hashes[i].size() << "\n";
    }
    o << "total: " << total << "\n";
    o.close();

    o.open("pure_hashes.txt");
    for (int i = 0; i < g_dump_hashes.size(); i++)
    {
        for (int j = 0; j < g_dump_hashes[i].size(); j++)
        {
            o << "0x" << std::setw(16) << std::setfill('0') << std::hex << std::uppercase << g_dump_hashes[i][j] << std::dec << std::nouppercase << "\n";
        }
    }
    o.close();

    std::cout << "done!\n";
    system("pause");
}