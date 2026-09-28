#include "symbols.hpp"

#include <dbghelp.h>

#include <cwchar>
#include <vector>

#pragma comment(lib, "dbghelp")

namespace
{
    struct symbol_buffer
    {
        SYMBOL_INFOW info {};
        wchar_t trailing_name [ MAX_SYM_NAME ] {};

        symbol_buffer( )
        {
            info.SizeOfStruct = sizeof( SYMBOL_INFOW );
            info.MaxNameLen = MAX_SYM_NAME;
        }
    };

    std::wstring kernel_image_path( )
    {
        wchar_t system_directory [ MAX_PATH ] {};
        UINT length = GetSystemDirectoryW( system_directory , MAX_PATH );
        if ( length == 0 || length >= MAX_PATH )
            return {};

        std::wstring path( system_directory , length );
        path += L"\\ntoskrnl.exe";
        return path;
    }

    std::wstring get_symbol_path( ) // should redo this. yet again, its 1am, i have class tmr
    {
        DWORD length = GetEnvironmentVariableW( L"_NT_SYMBOL_PATH" , nullptr , 0 );
        if ( length > 1 )
        {
            std::vector<wchar_t> value( length );
            GetEnvironmentVariableW( L"_NT_SYMBOL_PATH" , value.data( ) , length );
            return value.data( );
        }
        return L"srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols";
    }
} // namespace

kernel_symbols::~kernel_symbols( )
{
    if ( initialized_ ) SymCleanup( process_ );
}

bool kernel_symbols::load( uint64_t nt_base )
{
    if ( initialized_ ) return module_base_ != 0;

    SymSetOptions( SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS );

    std::wstring symbol_path = get_symbol_path( );
    if ( !SymInitializeW( process_ , symbol_path.c_str( ) , false ) ) {
        LOG( "[-] SymInitialize failed: %lu\n" , GetLastError( ) );
        return false;
    }
    initialized_ = true;

    std::wstring image_path = kernel_image_path( );
    module_base_ = SymLoadModuleExW( process_ , nullptr , image_path.c_str( ) , L"nt" , nt_base , 0 , nullptr , 0 );
    if ( !module_base_ ) {
        LOG( "[-] PDB load failed: %lu\n" , GetLastError( ) );
        return false;
    }

    IMAGEHLP_MODULEW64 module {};
    module.SizeOfStruct = sizeof( module );
    if ( SymGetModuleInfoW64( process_ , module_base_ , &module ) ) {
        LOG( "[+] PDB loaded: %ls\n" , module.LoadedPdbName );
    }
    else {
        LOG( "[+] kernel symbols loaded\n" );
    }
    return true;
}

uint64_t kernel_symbols::address( const wchar_t* symbol_name ) const
{
    if ( !module_base_ ) return 0;

    std::wstring qualified = L"nt!";
    qualified += symbol_name;
    symbol_buffer symbol;
    if ( !SymFromNameW( process_ , qualified.c_str( ) , &symbol.info ) ) return 0;
    return symbol.info.Address;
}

bool kernel_symbols::field_offset( const wchar_t* type_name , const wchar_t* field_name , uint32_t* offset ) const
{
    if ( !module_base_ || !offset )
        return false;

    symbol_buffer type;
    if ( !SymGetTypeFromNameW( process_ , module_base_ , type_name , &type.info ) ) {
        return false;
    }

    ULONG child_count = 0;
    if ( !SymGetTypeInfo( process_ , module_base_ , type.info.TypeIndex , TI_GET_CHILDRENCOUNT , &child_count ) || child_count == 0 ) {
        return false;
    }

    size_t bytes = sizeof( TI_FINDCHILDREN_PARAMS );
    if ( child_count > 1 ) bytes += sizeof( ULONG ) * ( child_count - 1 );
    std::vector<uint8_t> storage( bytes );
    auto children = reinterpret_cast< TI_FINDCHILDREN_PARAMS* >( storage.data( ) );
    children->Count = child_count;
    children->Start = 0;
    if ( !SymGetTypeInfo( process_ , module_base_ , type.info.TypeIndex , TI_FINDCHILDREN , children ) ) {
        return false;
    }

    for ( ULONG i = 0; i < child_count; ++i ) {
        wchar_t* name = nullptr;
        if ( !SymGetTypeInfo( process_ , module_base_ , children->ChildId [ i ] , TI_GET_SYMNAME , &name ) || !name ) {
            continue;
        }

        bool match = _wcsicmp( name , field_name ) == 0;
        LocalFree( name );
        if ( !match ) continue;

        ULONG field_offset = 0;
        if ( !SymGetTypeInfo( process_ , module_base_ , children->ChildId [ i ] , TI_GET_OFFSET , &field_offset ) ) {
            return false;
        }
        *offset = field_offset;
        return true;
    }
    return false;
}
