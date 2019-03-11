#pragma once

#ifndef DOS_HEADER_H
#define DOS_HEADER_H

#include "common.h"

namespace pe_parser
{
	class dos_header_t
	{
	public:

#pragma pack (1)
		struct dos_header_struct_t
		{
			uint16_t signature_;
			uint16_t lastsize;
			uint16_t nblocks;
			uint16_t nreloc;
			uint16_t hdrsize;
			uint16_t minalloc;
			uint16_t maxalloc;
			uint16_t ss_pointer;
			uint16_t sp_pointer;
			uint16_t checksum;
			uint16_t ip_pointer;
			uint16_t cs_pointer;
			uint16_t relocpos;
			uint16_t noverlay;
			uint16_t reserved1_[4];
			uint16_t oem_id;
			uint16_t oem_info;
			uint16_t reserved2_[10];
			uint32_t e_lfanew; // Offset to PE header
		};
#pragma pack ()

		dos_header_t(ADDRINT dos_header_address);
		~dos_header_t() = default;

		const uint16_t mz_signature = 0x5a4d;

		bool check_dos_header();
		dos_header_struct_t& get_dos_header();
		bool dump_dos_header();
	private:
		struct dos_header_struct_t dos_header;
		bool dos_header_correct;
	};
}

#endif // !DOS_HEADER_H