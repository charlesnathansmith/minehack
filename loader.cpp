/********************
*
* Minesweeper 64-bit Hack
* Nathan Smith
* https://github.com/charlesnathansmith/minehack
*
* External injector and data retriever
*
********************/

#include <iostream>
#include <Windows.h>
#include <AclAPI.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

// Default injected DLL path
constexpr WCHAR default_dllpath[] = L"injected.dll";

// Macro to avoid typing the same error/return block over and over
#define werr_closeh(error) { std::wcout << error << std::endl; close_ms(); return false; }

// For managing access to Minesweeper process
// We're never going to open multiple processes so easiest just to use a global
struct proc_t
{
    DWORD pid;
    HANDLE handle;
};

proc_t ms_proc = { 0 };

// Simple board format used by remote hook
#pragma pack(push,1)
struct board_t
{
    size_t counter;
    uint8_t width, height;
    uint8_t tiles[65536];
};
#pragma pack(pop)

// Copy security descriptor from one file to another
// Needed to make sure Minesweeper can load our injection DLL
bool copy_dacl(LPCWSTR dst, LPCWSTR src)
{
    DWORD sd_size;

    // Get security descriptor buffer size needed
    GetFileSecurity(src, DACL_SECURITY_INFORMATION, 0, 0, &sd_size);
    PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR) new uint8_t[sd_size];

    // MSDN says SetFileSecurity is obsolete but doesn't mention it for GetFileSecurity
    // SetNamedSecurityInfo seems to be a bit finicky so we'll stick with this for now,
    // but this may need updated in the future
    if (!GetFileSecurity(src, DACL_SECURITY_INFORMATION, sd, sd_size, &sd_size) ||
        !SetFileSecurity(dst, DACL_SECURITY_INFORMATION, sd))
    {
        delete[] sd;
        return false;
    }

    delete[] sd;
    return true;
}

// Get PID for process by .exe name
DWORD get_pid(LPCWSTR exe_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W proc;
    proc.dwSize = sizeof(proc);
    size_t name_len = wcslen(exe_name);

    while (Process32Next(snap, &proc))
        if (!_wcsnicmp(proc.szExeFile, exe_name, name_len))
        {
            CloseHandle(snap);
            return proc.th32ProcessID;
        }

    CloseHandle(snap);
    return 0;
}

uintptr_t get_module_base(DWORD pid, LPCWSTR mod_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    MODULEENTRY32 mod;
    mod.dwSize = sizeof(MODULEENTRY32);
    size_t name_len = wcslen(mod_name);

    if (!Module32First(snap, &mod))
        return 0;

    do
    {
        if (!_wcsnicmp(mod.szModule, mod_name, name_len))
        {
            CloseHandle(snap);
            return (uintptr_t) mod.modBaseAddr;
        }
    } while (Module32Next(snap, &mod));
    
    CloseHandle(snap);
    return 0;
}

// Open Minesweeper.exe process
bool open_ms()
{
    if (ms_proc.pid)
        return &ms_proc;

    DWORD pid = get_pid(L"Minesweeper.exe");

    if (!pid)
        return false;

    HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);

    if (!handle)  // INVALID_HANDLE_VALUE not cool enough for this part of the API
        return false;

    ms_proc.pid = pid;
    ms_proc.handle = handle;

    return true;
}

// Close Minesweeper.exe process
void close_ms()
{
    CloseHandle(ms_proc.handle);
    ms_proc.pid = 0;
    ms_proc.handle = 0;
}

// Inject hook DLL into Minesweeper process
// Adapted from http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html
bool inject(LPCWSTR abs_dllpath)
{
    std::wcout << "Minesweeper.exe PID: " << ms_proc.pid << std::endl;
    std::wcout << "DLL path: " << abs_dllpath << std::endl;

    std::wcout << "Updating DLL access permissions" << std::endl;

    // Minesweeper needs to be able to access injected DLL file or LoadLibrary will fail
    // Just copying the DACL from a DLL we know it can load (any system library will work fine)
    if (!copy_dacl(abs_dllpath, L"C:\\Windows\\System32\\user32.dll"))
    {
        std::wcout << "Couldn't update DLL permissions\n";
        std::wcout << "Minesweeper.exe might not be able to load it" << std::endl;
        // Not necessarily a fatal error so we'll press on
    }

    // Allocate a buffer for abs_dllpath in remote process
    size_t pathsize = (wcslen(abs_dllpath) + 1) * sizeof(WCHAR);
    void *ms_dllpath = VirtualAllocEx(ms_proc.handle, NULL, pathsize, MEM_COMMIT, PAGE_READWRITE);

    if (!ms_dllpath)
        werr_closeh("Couldn't allocate remote buffer for DLL path");

        // Copy DLL path into remote buffer
    if (!WriteProcessMemory(ms_proc.handle, ms_dllpath, abs_dllpath, pathsize, NULL))
        werr_closeh("Couldn't copy DLL path to remote buffer");

    std::wcout << "DLL path written to remote address: " << std::hex << (unsigned long long) ms_dllpath << std::endl;

    // kernel32.dll is (unofficially) guaranteed to load at the same base address for every process,
    // primarily because Windows does the same thing we're doing here in certain situations
    // (See http://www.nynaeve.net/?p=198)
    // We can't rely on that for our injected DLL, but it's a reasonably safe assumption here
    LPTHREAD_START_ROUTINE loadlibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    std::wcout << "Remote LoadLibraryW at: " << (unsigned long long) loadlibrary << std::endl;

    // Launch remote thread to load DLL
    HANDLE thread = CreateRemoteThread(ms_proc.handle, NULL, 0, loadlibrary, ms_dllpath, 0, NULL);

    if (!thread)
        werr_closeh("Couldn't launch LoadLibraryW remotely\n");

    std::wcout << "Remote injection thread launched" << std::endl;

    WaitForSingleObject(thread, INFINITE);
    VirtualFreeEx(ms_proc.handle, ms_dllpath, 0, MEM_RELEASE);
    CloseHandle(thread);

    std::wcout << "Remote injection thread completed -- DLL should be loaded\n" << std::endl;

    return true;
}

bool start_hook(LPCWSTR dll_file)
{
    // Get remote base address for injected dll
    // Converting void*s to uintptr_t so doing arithmetic with it works properly
    uintptr_t rem_dll_base = get_module_base(ms_proc.pid, dll_file);

    if (!rem_dll_base)
        werr_closeh("Couldn't get remote base address for " << dll_file);
    
    std::wcout << "Remote base address for " << dll_file << ": " << std::hex << rem_dll_base << '\n';

    // Calculate remote addresses
    // Odds are the remote injected DLL will be at the same base address as the local version,
    // but we can't rely on that like we could with kernel32.dll

    // Load the injected DLL locally
    HMODULE loc_dll = LoadLibrary(dll_file);

    // loc_dll probably already is the local base address, but that isn't guaranteed by the API
    uintptr_t loc_dll_base = get_module_base(GetCurrentProcessId(), dll_file);

    if (!loc_dll || !loc_dll_base)
        werr_closeh("Couldn't get local base address for " << dll_file);

    std::wcout << "Local base address for " << dll_file << ": " << loc_dll_base << '\n';
    
    // Get local start() address
    uintptr_t loc_start = (uintptr_t) GetProcAddress(loc_dll, "start");
    
    if (!loc_start)
        werr_closeh("Couldn't get local address for start()");

    // Calulate remote start() address
    uintptr_t rem_start = loc_start - loc_dll_base + rem_dll_base;
    std::wcout << "Local start() address: " << loc_start << '\n';
    std::wcout << "Remote start() address: " << rem_start << '\n';
    
    // Get GameAssembly.dll base address in remote process
    uintptr_t game_base = get_module_base(ms_proc.pid, L"gameassembly.dll");

    if (!loc_start)
        werr_closeh("Couldn't get GameAssembly.dll base address");

    std::wcout << "GameAssembly.dll base address: " << game_base << '\n';
    std::wcout << "Launching remote start() thread" << '\n';

    // Launch start(game_base) in remote process (we pass it the base address of GameAssembly.dll)
    if (!CreateRemoteThread(ms_proc.handle, NULL, 0, (LPTHREAD_START_ROUTINE)rem_start, (LPVOID) game_base, 0, NULL))
        werr_closeh("Failed to launch remote start() thread");

    std::wcout << "Thread Launched" << std::endl;

    return true;
}

// Get remote board address
uintptr_t rem_board_address(LPCWSTR dll_file)
{
    HMODULE loc_dll = LoadLibrary(dll_file);
    
    if (!loc_dll)
        return 0;
    
    uintptr_t loc_board = (uintptr_t) GetProcAddress(loc_dll, "board");

    // We should really cache these results somewhere instead of searching for them again
    uintptr_t rem_dll_base = get_module_base(ms_proc.pid, dll_file);
    uintptr_t loc_dll_base = get_module_base(GetCurrentProcessId(), dll_file);

    if (!loc_board || !rem_dll_base || !loc_dll_base)
        return 0;

    return loc_board - loc_dll_base + rem_dll_base;
}

void print_board(board_t& board)
{
    std::wcout << std::dec << "width: " << (int)board.width << "  height: " << (int)board.height << '\n';

    // Board data starts from lower left corner,
    // Reads across to bottom right, then repeats upward row by row
    // We need to start from top row and work backwards through data
    for (size_t row = board.height; row; row--)
    {
        uint8_t *row_start = board.tiles + (row - 1) * (size_t) board.width;

        for (size_t col = 0; col < board.width; col++)
            std::wcout << '[' << ((row_start[col]) ? 'X' : ' ') << ']';

        std::cout << '\n';
    }

    std::cout << '\n' << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
    std::wcout << "\nMinesweeper 64-bit Hack\n"
                 "mineserver.exe [injected.dll]\n\n"
                 "Make sure Minesweeper is open before running this program\n"
                 "Try running this as Administrator if there are issues during injection\n"
                 "Boards are not generated until after the first tile is cleared\n\n";

    // Get absolute path to DLL
    WCHAR abs_dllpath[MAX_PATH], *dll_file;
    GetFullPathName((argc > 1) ? argv[1] : default_dllpath, MAX_PATH, abs_dllpath, &dll_file);

    // Be sure to add shlwapi.lib to "Additional Dependencies" in linker settings to use PathFileExists with VS
    if (!PathFileExists(abs_dllpath))
        werr_closeh("Couldn't find DLL: " << abs_dllpath);
        
    std::wcout << "Attempting hook injection...\n" << std::endl;

    if (!open_ms())
        werr_closeh("Couldn't open Minesweeper.exe process");

    if (!inject(abs_dllpath))
        werr_closeh("Failed to inject DLL");

    if (!start_hook(dll_file))
        werr_closeh("Failed to start remote hook");

    uintptr_t rem_board = rem_board_address(dll_file);

    if (!rem_board)
        werr_closeh("Failed getting remote board address");

    std::wcout << "Remote board address: " << rem_board << "\n\n";
    std::wcout << "Polling for board updates...\n" << std::endl;

    static board_t board = { 0 }; // It's a bit chonky for the stack
    size_t last_board = 0;

    while (true)
    {
        Sleep(500);

        // Read board counter
        if (!ReadProcessMemory(ms_proc.handle, (void*) rem_board, &board.counter, sizeof(board.counter), NULL))
        {
            std::wcout << "Error reading board counter\n";
            continue;
        }

        // Check if the board has been updated
        if (board.counter != last_board)
        {
            last_board = board.counter;

            // Read board dimensions
            if (!ReadProcessMemory(ms_proc.handle, (void*)(rem_board + sizeof(board.counter)), &board.width, sizeof(board.width)*2, NULL))
            {
                std::wcout << "Error reading board dimensions\n";
                continue;
            }

            // Board can't have 0 width or height - it isn't updating correctly if this happens
            if (!board.width || !board.height)
            {
                std::wcout << "Invalid board dimensions -- width: " << (int)board.width << ", height: " << (int)board.height << '\n';
                continue;
            }

            // Read tile data
            if (!ReadProcessMemory(ms_proc.handle, (void*)(rem_board + sizeof(board.counter) + sizeof(board.width) * 2),
                                   board.tiles, (size_t) board.width * (size_t) board.height, NULL))
            {
                std::wcout << "Error reading tile data\n";
                continue;
            }

            print_board(board);
        }
    }

    // Never reached
    close_ms();
    return 0;
}
