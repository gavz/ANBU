#pragma once

#ifndef SECTION_HEADER_H
#define SECTION_HEADER_H

#include "common.h"

namespace pe_parser
{
	class section_header_t
	{
	public:
#pragma pack(1)
		struct section_struct_t
		{
			uint8_t name[8];
			uint32_t virtualSize;
			uint32_t virtualAddress;
			uint32_t sizeOfRawData;
			uint32_t pointerToRawData;
			uint32_t pointerToRelocations;
			uint32_t pointerToLineNumbers;
			uint16_t numberOfRelocations;
			uint16_t numberOfLineNumbers;
			uint32_t characteristics;
		};
#pragma pack()
		enum section_flags_enum_t
		{
			RESERVED_SECTION_FLAG_0_k = 0x00000000,
			RESERVED_SECTION_FLAG_1_k = 0x00000001,
			RESERVED_SECTION_FLAG_2_k = 0x00000002,
			RESERVED_SECTION_FLAG_4_k = 0x00000004,
			RESERVED_SECTION_FLAG_10_k = 0x00000010,
			RESERVED_SECTION_FLAG_400_k = 0x00000400,
			IMAGE_SCN_TYPE_NO_PAD_k = 0x00000008,
			IMAGE_SCN_CNT_CODE_k = 0x00000020,
			IMAGE_SCN_CNT_INITIALIZED_DATA_k = 0x00000040,
			IMAGE_SCN_CNT_UNINITIALIZED_DATA_k = 0x00000080,
			IMAGE_SCN_LNK_OTHER_k = 0x00000100,
			IMAGE_SCN_LNK_INFO_k = 0x00000200,
			IMAGE_SCN_LNK_REMOVE_k = 0x00000800,
			IMAGE_SCN_LNK_COMDAT_k = 0x00001000,
			IMAGE_SCN_GPREL_k = 0x00008000,
			IMAGE_SCN_MEM_PURGEABLE_k = 0x00020000,
			IMAGE_SCN_MEM_16BIT_k = 0x00020000,
			IMAGE_SCN_MEM_LOCKED_k = 0x00040000,
			IMAGE_SCN_MEM_PRELOAD_k = 0x00080000,
			IMAGE_SCN_ALIGN_1BYTES_k = 0x00100000,
			IMAGE_SCN_ALIGN_2BYTES_k = 0x00200000,
			IMAGE_SCN_ALIGN_4BYTES_k = 0x00300000,
			IMAGE_SCN_ALIGN_8BYTES_k = 0x00400000,
			IMAGE_SCN_ALIGN_16BYTES_k = 0x00500000,
			IMAGE_SCN_ALIGN_32BYTES_k = 0x00600000,
			IMAGE_SCN_ALIGN_64BYTES_k = 0x00700000,
			IMAGE_SCN_ALIGN_128BYTES_k = 0x00800000,
			IMAGE_SCN_ALIGN_256BYTES_k = 0x00900000,
			IMAGE_SCN_ALIGN_512BYTES_k = 0x00A00000,
			IMAGE_SCN_ALIGN_1024BYTES_k = 0x00B00000,
			IMAGE_SCN_ALIGN_2048BYTES_k = 0x00C00000,
			IMAGE_SCN_ALIGN_4096BYTES_k = 0x00D00000,
			IMAGE_SCN_ALIGN_8192BYTES_k = 0x00E00000,
			IMAGE_SCN_LNK_NRELOC_OVFL_k = 0x01000000,
			IMAGE_SCN_MEM_DISCARDABLE_k = 0x02000000,
			IMAGE_SCN_MEM_NOT_CACHED_k = 0x04000000,
			IMAGE_SCN_MEM_NOT_PAGED_k = 0x08000000,
			IMAGE_SCN_MEM_SHARED_k = 0x10000000,
			IMAGE_SCN_MEM_EXECUTE_k = 0x20000000,
			IMAGE_SCN_MEM_READ_k = 0x40000000,
			IMAGE_SCN_MEM_WRITE_k = 0x80000000
		};

		section_header_t(ADDRINT address, uint32_t number_of_sections, uint32_t size_of_image);
		~section_header_t() = default;

		std::vector<section_struct_t>& get_sections();
		section_struct_t* get_section_by_rva(uint64_t rva);
		section_struct_t* get_section_by_offset(uint64_t offset);
		bool dump_sections();
		bool are_sections_correct();

	private:
		std::vector<section_struct_t> sections;
		uint32_t number_of_sections;
		bool sections_are_correct;
	};
}

#endif // !SECTION_HEADER_H
