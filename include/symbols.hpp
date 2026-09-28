#pragma once

#include "common.hpp"

#include <string>

class kernel_symbols
{
public:
    kernel_symbols( ) = default;
    ~kernel_symbols( );

    kernel_symbols( const kernel_symbols& ) = delete;
    kernel_symbols& operator=( const kernel_symbols& ) = delete;

    bool load( uint64_t nt_base );
    uint64_t address( const wchar_t* symbol_name ) const;
    bool field_offset( const wchar_t* type_name , const wchar_t* field_name , uint32_t* offset ) const;

private:
    HANDLE process_ = GetCurrentProcess( );
    DWORD64 module_base_ = 0;
    bool initialized_ = false;
};
