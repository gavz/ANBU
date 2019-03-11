#pragma once

#ifndef OPTIONAL_HEADER_H
#define OPTIONAL_HEADER_H

#include "common.h"

namespace pe_parser
{
	class optional_header_t
	{
	public:
#pragma pack(1)
		struct optional_image_only_p32_t
		{
			uint16_t magic;
			uint8_t majorLinkerVersion;
			uint8_t minorLinkerVersion;
			uint32_t sizeOfCode;
			uint32_t sizeOfInitializedData;
			uint32_t sizeOfUnInitializedData;
			uint32_t addressOfEntryPoint;
			uint32_t baseOfCode;
			uint32_t baseOfData;
			uint32_t imageBase;
			uint32_t sectionAlignment;
			uint32_t fileAlignment;
			uint16_t majorOperatingSystemVersion;
			uint16_t minorOperatingSystemVersion;
			uint16_t majorImageVersion;
			uint16_t minorImageVersion;
			uint16_t majorSubsystemVersion;
			uint16_t minorSubsystemVersion;
			uint32_t win32VersionValue;
			uint32_t sizeOfImage;
			uint32_t sizeOfHeaders;
			uint32_t checkSum;
			uint16_t subsystem;
			uint16_t dllCharacteristics;
			uint32_t sizeOfStackReserve;
			uint32_t sizeOfStackCommit;
			uint32_t sizeOfHeapReserve;
			uint32_t sizeOfHeapCommit;
			uint32_t loaderFlags;
			uint32_t numberOfRvaAndSizes;
		};
#pragma pack()
#pragma pack(1)
		struct optional_image_only_p64_t {
			uint16_t magic;
			uint8_t majorLinkerVersion;
			uint8_t minorLinkerVersion;
			uint32_t sizeOfCode;
			uint32_t sizeOfInitializedData;
			uint32_t sizeOfUnInitializedData;
			uint32_t addressOfEntryPoint;
			uint32_t baseOfCode;
			uint64_t imageBase;
			uint32_t sectionAlignment;
			uint32_t fileAlignment;
			uint16_t majorOperatingSystemVersion;
			uint16_t minorOperatingSystemVersion;
			uint16_t majorImageVersion;
			uint16_t minorImageVersion;
			uint16_t majorSubsystemVersion;
			uint16_t minorSubsystemVersion;
			uint32_t win32VersionValue;
			uint32_t sizeOfImage;
			uint32_t sizeOfHeaders;
			uint32_t checkSum;
			uint16_t subsystem;
			uint16_t dllCharacteristics;
			uint64_t sizeOfStackReserve;
			uint64_t sizeOfStackCommit;
			uint64_t sizeOfHeapReserve;
			uint64_t sizeOfHeapCommit;
			uint32_t loaderFlags;
			uint32_t numberOfRvaAndSizes;
		};
#pragma pack()

		union optional_image_only_union_t
		{
			optional_image_only_p32_t optional_32;
			optional_image_only_p64_t optional_64;
		};

		enum optional_header_enum_t 
		{
			rom_image_k = 0x107,
			pe32_k = 0x10B,
			pe64_k = 0x20B
		};

		enum optional_header_subsystem_enum_t 
		{
			IMAGE_SUBSYSTEM_UNKNOWN_k = 0,
			IMAGE_SUBSYSTEM_NATIVE_k = 1,
			IMAGE_SUBSYSTEM_WINDOWS_GUI_k = 2,
			IMAGE_SUBSYSTEM_WINDOWS_CUI_k = 3,
			IMAGE_SUBSYSTEM_OS2_CUI_k = 5,
			IMAGE_SUBSYSTEM_POSIX_CUI_k = 7,
			IMAGE_SUBSYSTEM_NATIVE_WINDOWS_k = 8,
			IMAGE_SUBSYSTEM_WINDOWS_CE_GUI_k = 9,
			IMAGE_SUBSYSTEM_EFI_APPLICATION_k = 10,
			IMAGE_SUBSYSTEM_EFI_BOOT__k = 11,
			IMAGE_SUBSYSTEM_EFI_RUNTIME__k = 12,
			IMAGE_SUBSYSTEM_EFI_ROM_k = 13,
			IMAGE_SUBSYSTEM_XBOX_k = 14,
			IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION_k = 16
		};

		enum optional_header_dllcharacteristics_enum_t 
		{
			RESERVED_DLL_CHARACTERISTICS_1_k = 0x0001,
			RESERVED_DLL_CHARACTERISTICS_2_k = 0x0002,
			RESERVED_DLL_CHARACTERISTICS_4_k = 0x0004,
			RESERVED_DLL_CHARACTERISTICS_8_k = 0x0008,
			IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA_k = 0x0020,
			IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE_k = 0x0040,
			IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY_k = 0x0080,
			IMAGE_DLLCHARACTERISTICS_NX_COMPAT_k = 0x0100,
			IMAGE_DLLCHARACTERISTICS_NO_ISOLATION_k = 0x0200,
			IMAGE_DLLCHARACTERISTICS_NO_SEH_k = 0x0400,
			IMAGE_DLLCHARACTERISTICS_NO_BIND_k = 0x0800,
			IMAGE_DLLCHARACTERISTICS_APPCONTAINER_k = 0x1000,
			IMAGE_DLLCHARACTERISTICS_WDM_DRIVER_k = 0x2000,
			IMAGE_DLLCHARACTERISTICS_GUARD_CF_k = 0x4000,
			IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE_k = 0x8000
		};

		optional_header_t(ADDRINT address);
		~optional_header_t() = default;

		optional_image_only_union_t& get_optional_image();
		bool is_64_bit_binary();
		bool is_optional_header_correct();
		bool dump_optional_image();
	private:
		bool optional_header_correct;
		bool is_64_bit;
		union optional_image_only_union_t optional_image;
	};
}

#endif // !OPTIONAL_HEADER_H
