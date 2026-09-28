#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>

inline void log_message( const char* format , ... )
{
    char message [ 2048 ] {};
    va_list arguments;
    va_start( arguments , format );
    vsnprintf( message , sizeof( message ) , format , arguments );
    va_end( arguments );
    OutputDebugStringA( message );
    fputs( message , stdout );
    fflush( stdout );
}

#define LOG(...) log_message(__VA_ARGS__)

inline bool is_kernel_address( uint64_t address )
{
    return address != 0 && ( address >> 48 ) == 0xFFFF;
}
