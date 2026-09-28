#pragma once

#include "common.hpp"
#include "vdm.hpp"

struct version_info
{
    uint32_t build;
    uint32_t ps_initial_system_process;
    uint32_t unique_process_id;
    uint32_t active_process_links;
    uint32_t token;
};

version_info pick_version( uint32_t build );
uint32_t get_windows_build( );
uint64_t ntos_base_from_system_info( );
uint64_t resolve_kernel_export( uint64_t nt_base , const char* export_name );
uint64_t resolve_pte_base_by_pattern( vdm::memory& memory , uint64_t nt_base , uint32_t build );
uint64_t find_swap_slot( vdm::memory& memory );
