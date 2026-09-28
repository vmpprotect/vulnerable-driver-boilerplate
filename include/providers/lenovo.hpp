#pragma once

#include "common.hpp"

#include <cstddef>

namespace providers
{
    class lenovo_diagnostics
    {
    public:
        lenovo_diagnostics( );
        ~lenovo_diagnostics( );

        lenovo_diagnostics( const lenovo_diagnostics& ) = delete;
        lenovo_diagnostics& operator=( const lenovo_diagnostics& ) = delete;

        bool read_phys( void* address , void* buffer , std::size_t size ) const;
        bool write_phys( void* address , void* buffer , std::size_t size ) const;

        static constexpr const wchar_t* device_path( )
        {
            return L"\\\\.\\LenovoDiagnosticsDriver";
        }

    private:
        HANDLE handle_ = INVALID_HANDLE_VALUE;
    };
} // namespace providers
