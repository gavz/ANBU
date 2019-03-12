#pragma once

#ifndef NT_HEADER_H
#define NT_HEADER_H

#include "common.h"


namespace pe_parser
{
	class nt_header_t
	{
	public:

#pragma pack (1)
		struct nt_coff_struct_t
		{
			uint32_t pe_signature;
			uint16_t machine;
			uint16_t numberOfSections;
			uint32_t timeDateStamp;
			uint32_t pointerToSymbolTable;
			uint32_t numberOfSymbols;
			uint16_t sizeOfOptionalHeader;
			uint16_t characteristics;
		};
#pragma pack ()

		enum nt_machine_enum_t {
			IMAGE_FILE_MACHINE_UNKNOWN_k = 0x0,
			IMAGE_FILE_MACHINE_AM33_k = 0x1d3,
			IMAGE_FILE_MACHINE_AMD64_k = 0x8664,
			IMAGE_FILE_MACHINE_ARM_k = 0x1c0,
			IMAGE_FILE_MACHINE_ARM64_k = 0xaa64,
			IMAGE_FILE_MACHINE_ARMNT_k = 0x1c4,
			IMAGE_FILE_MACHINE_EBC_k = 0xebc,
			IMAGE_FILE_MACHINE_I386_k = 0x014C,
			IMAGE_FILE_MACHINE_IA64_k = 0x0200,
			IMAGE_FILE_MACHINE_M32R_k = 0x9041,
			IMAGE_FILE_MACHINE_MIPS16_k = 0x266,
			IMAGE_FILE_MACHINE_MIPSFPU_k = 0x366,
			IMAGE_FILE_MACHINE_MIPSFPU16_k = 0x466,
			IMAGE_FILE_MACHINE_POWERPC_k = 0x1f0,
			IMAGE_FILE_MACHINE_POWERPCFP_k = 0x1f1,
			IMAGE_FILE_MACHINE_R4000_k = 0x166,
			IMAGE_FILE_MACHINE_RISCV32_k = 0x5032,
			IMAGE_FILE_MACHINE_RISCV64_k = 0x5064,
			IMAGE_FILE_MACHINE_RISCV128_k = 0x5128,
			IMAGE_FILE_MACHINE_SH3_k = 0x1a2,
			IMAGE_FILE_MACHINE_SH3DSP_k = 0x1a3,
			IMAGE_FILE_MACHINE_SH4_k = 0x1a6,
			IMAGE_FILE_MACHINE_SH5_k = 0x1a8,
			IMAGE_FILE_MACHINE_THUMB_k = 0x1c2,
			IMAGE_FILE_MACHINE_WCEMIPSV2_k = 0x169
		};

		enum nt_characteristics_enum_t {
			IMAGE_FILE_RELOCS_STRIPPED_k = 0x0001,
			IMAGE_FILE_EXECUTABLE_IMAGE_k = 0x0002,
			IMAGE_FILE_LINE_NUMS_STRIPPED_k = 0x0004,
			IMAGE_FILE_LOCAL_SYMS_STRIPPED_k = 0x0008,
			IMAGE_FILE_AGGRESSIVE_WS_TRIM_k = 0x0010,
			IMAGE_FILE_LARGE_ADDRESS_AWARE_k = 0x0020,
			RESERVED_CHARACTERISTIC_k = 0x0040,
			IMAGE_FILE_BYTES_REVERSED_LO_k = 0x0080,
			IMAGE_FILE_32BIT_MACHINE_k = 0x0100,
			IMAGE_FILE_DEBUG_STRIPPED_k = 0x0200,
			IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP_k = 0x0400,
			IMAGE_FILE_NET_RUN_FROM_SWAP_k = 0x0800,
			IMAGE_FILE_SYSTEM_k = 0x1000,
			IMAGE_FILE_DLL_k = 0x2000,
			IMAGE_FILE_UP_SYSTEM_ONLY_k = 0x4000,
			IMAGE_FILE_BYTES_REVERSED_HI_k = 0x8000
		};

		const uint32_t correct_pe_signature_k = 0x4550;	// PE in little-endian

		nt_header_t(ADDRINT address);
		~nt_header_t() = default;

		nt_coff_struct_t& get_nt_header();
		bool is_pe_header_correct();
		bool dump_nt_header();
	private:
		nt_coff_struct_t nt_coff_header;
		bool pe_header_correct;
	};
}

#endif // !NT_HEADER_H
