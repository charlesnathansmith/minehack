/********************
* 
* Minesweeper 64-bit Hack
* Nathan Smith
* https://github.com/charlesnathansmith/minehack
* 
* Injected DLL
* 
********************/

#define WIN32_LEAN_AND_MEAN 
#include <stdint.h>
#include <Windows.h>

#define DLLEXPORT extern "C" __declspec(dllexport)

/**********
* GameAssembly.dll RVAs
**********/

enum
{
    SM_jmp_RVA =       0xB58767,  // This is where the relative jmp needs to be inserted near the end of $$SetupMines
    trampoline_RVA =   0xB58201,  // Some unused space near $$GenerateBoard that can hold the trampoline (algn_180B58201)

    TypeInfo_RVA =    0x31DA0D8,  // *Gameplay_Board_Data_ITileGridData_TypeInfo, stored as a global
    GridData_RVA =      0xC4710,  // Unnamed function that retrieves grid data
    GetTile_RVA =      0xB58130,  // Gameplay_Board_Components_GameplayBoard_object_$$GetTile
};

/**********
* Board data
**********/

#pragma pack(push,1)
// Simple board format
struct board_t
{
    uint64_t counter;
    uint8_t width, height;
    uint8_t tiles[65536];
};

// Gameplay_Board_Components_Tiles_GameplayTile_o memory layout
// (The part we care about, anyway)
struct tile_t
{
    uint8_t filler[0x1c]; // +0
    uint8_t is_mine;      // +0x1c
};
#pragma pack(pop)

// Store board information for external program
DLLEXPORT board_t board = { 0 };

/**********
* Addresses
**********/

// Conventionally these would be void*s, but doing arithmetic with those
// can pose challenges and the syntax gets messy
uintptr_t trampoline_addr = 0;
uintptr_t SM_jmp_addr = 0;
uintptr_t *pTypeInfo = 0;

typedef tile_t* (__stdcall* GetTile_t) (void*, int32_t, void*);
GetTile_t GetTile = 0;

typedef int64_t (__stdcall* GridData_t) (int32_t, void*, void*);
GridData_t GridData = 0;

/**********
* Hooks
**********/

// Hook for end of Gameplay_BoardGenerators_BoardGenerator$$SetupMines
// Reads mine information from grid
void __stdcall SetupMines_hook(void* grid)
{
    if (!grid || !GridData || !pTypeInfo || !GetTile)
        return;

    // Get number of board tiles
    size_t num_tiles = GridData(3, (void*) *pTypeInfo, grid);

    if (num_tiles > 65536)
        return;

    // Get width and calculate height
    board.width = GridData(1, (void*) *pTypeInfo, grid);
    board.height = num_tiles / board.width;

    // Read board
    for (size_t i = 0; i < num_tiles; i++)
        board.tiles[i] = GetTile(grid, i, 0)->is_mine;  // Throws an exception if out of bounds, but probably unrecoverable by then anyway

    // Update board counter to signal new board is ready
    board.counter++;
}

// Bridge to SetupMines_hook
// Visual Studio doesn't support inline asm for x64, so we'll just assemble it ourselves
// Context is just before $$SetupMines epilog, grid pointer is still in rbp
uint8_t SM_Bridge[] = // Call SetupMines_hook(grid)
                      "\x48\x89\xE9"							 // mov rcx, rbp ; grid
                      "\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00" // mov r10, SetupMines_hook
                      "\x41\xFF\xD2"							 // call r10
                      // Replace clobbered epilog and ret
                      "\x48\x83\xC4\x40"                         // add rsp, 0x40
                      "\x41\x5C"                                 // pop r12
                      "\x5D"                                     // pop rbp
                      "\x5B"                                     // pop rbx
                      "\xC3";									 // ret

// Initialize SM_Bridge
// Fills in the address of SetupMines_hook and makes it executable
// Size is SM_Bridge - 1 since building it as a string literal tacks a null onto the end
bool init_SM_Bridge()
{
    *((uintptr_t*)(SM_Bridge + 5)) = (uintptr_t) SetupMines_hook;
    DWORD old;
    return VirtualProtect(SM_Bridge, sizeof(SM_Bridge) - 1, PAGE_EXECUTE_READWRITE, &old);
}

// Trampoline to SM_Bridge
// Address gets filled in and this gets copied to trampoline_addr
// See eg. http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html
uint8_t trampoline[] = "\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00"   // mov r10, jmp_addr
                       "\x41\xFF\xE2";                              // jmp r10

// Fill in address for SM_Bridge in trampoline
void init_trampoline()
{
    *((uintptr_t*)(trampoline + 2)) = (uintptr_t) SM_Bridge;
}

/**********
* Installation
**********/

// Calculate addresses within GameAssembly.dll
bool init_func_ptrs(uintptr_t base)
{
    if (!base)
        return false;

    trampoline_addr = base + trampoline_RVA;
    SM_jmp_addr = base + SM_jmp_RVA;
    pTypeInfo = (uintptr_t*)(base + TypeInfo_RVA);
    GetTile = (GetTile_t)(base + GetTile_RVA);
    GridData = (GridData_t)(base + GridData_RVA);

    return true;
}

// Setup and install hook
DLLEXPORT DWORD WINAPI start(uintptr_t game_base)
{
    // Calculate addresses from RVAs
    if (!init_func_ptrs(game_base))
        return false;

    // Setup SM_Bridge
    if (!init_SM_Bridge())
        return false;

    // Setup trampoline to jump to SM_Bridge
    init_trampoline();

    DWORD old, unused;

    // Copy trampoline to the unused space we found at trampoline_addr,
    // close enough to SetupMines for a relative jmp to reach
    if (!VirtualProtect((void*)trampoline_addr, sizeof(trampoline) - 1, PAGE_EXECUTE_READWRITE, &old))
        return false;

    memcpy((void*)trampoline_addr, trampoline, sizeof(trampoline) - 1);

    // Prepare relative jmp to SM_trampoline
    char rel_jmp[] = "\xE9\x00\x00\x00\x00"    // jmp (offset)
                     "\x00\x00\x00";           // Original next bytes to allow atomic write

    // Insert offset from beginning of ins after relative jmp to the beginning of the trampoline
    *((uint32_t*)(rel_jmp + 1)) = trampoline_addr - (SM_jmp_addr + 5);

    // Setup for atomic write
    // 
    // Since the relative jmp is being inserted into live code,
    // we'd prefer to insert it all at once so we don't risk another
    // thread trying to execute it while we're in the middle of copying it over
    // 
    // We can insert a 64-bit (8-byte) value in one go, but the jmp instruction is only 5
    // bytes, so we'll just copy the existing next 3 bytes into what we plan to write
    //
    // This isn't really that important here, since the instructions after the jmp are never
    // excecuted after it is installed, and this area is only reached when starting a new
    // board anyway, but it's good practice
    memcpy((void*)(rel_jmp + 5), (void*)(SM_jmp_addr + 5), 3);

    if (!VirtualProtect((void*)SM_jmp_addr, 8, PAGE_EXECUTE_READWRITE, &old))
        return false;

    // Write the relative jmp
    *((uint64_t*)SM_jmp_addr) = *((uint64_t*)rel_jmp);

    // Zip it back up - not really necessary
    VirtualProtect((void*)SM_jmp_addr, 8, old, &unused);

    return true;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
    return TRUE;
}
