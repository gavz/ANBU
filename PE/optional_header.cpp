
#include "optional_header.h"

extern FILE *logfile; // log file handler

namespace pe_parser
{
	optional_header_t::optional_header_t(ADDRINT address)
	{
		size_t copied_size, size_to_copy, size_magic_value = sizeof(uint16_t);
		uint16_t magic_value;
		optional_header_correct = true;
		is_64_bit = false;

		copied_size = PIN_SafeCopy((VOID*)&magic_value, (const VOID*)address, size_magic_value);

		if (copied_size != size_magic_value)
		{
			fprintf(stderr, "Error, not possible to read magic value from file\n");
			optional_header_correct = false;
			return;
		}

		if (magic_value == pe32_k)
		{
			is_64_bit = false;
			size_to_copy = sizeof(optional_image_only_p32_t);

			copied_size = PIN_SafeCopy((VOID*)&optional_image.optional_32, (const VOID*)address, size_to_copy);
		}
		else if (magic_value == pe64_k)
		{
			is_64_bit = true;
			size_to_copy = sizeof(optional_image_only_p64_t);

			copied_size = PIN_SafeCopy((VOID*)&optional_image.optional_64, (const VOID*)address, size_to_copy);
		}
		else
		{
			fprintf(stderr, "Magic value is not correct: 0x%x\n", magic_value);
			optional_header_correct = false;
			return;
		}

		if (copied_size != size_to_copy)
			optional_header_correct = false;
	}

	optional_header_t::optional_image_only_union_t& optional_header_t::get_optional_image()
	{
		return optional_image;
	}

	bool optional_header_t::is_64_bit_binary()
	{
		return is_64_bit;
	}

	bool optional_header_t::is_optional_header_correct()
	{
		return optional_header_correct;
	}

	bool optional_header_t::dump_optional_image()
	{
		if (!optional_header_correct)
			return false;

		fprintf(logfile, "================== DUMP OPTIONAL HEADER ===================\n");
		if (is_64_bit)
		{
			fprintf(logfile, "\t+Magic: 0x%x\n", optional_image.optional_64.magic);
			fprintf(logfile, "\t+MajorLinkerVersion: 0x%x\n", optional_image.optional_64.majorLinkerVersion);
			fprintf(logfile, "\t+MenorLinkerVersion: 0x%x\n", optional_image.optional_64.minorLinkerVersion);
			fprintf(logfile, "\t+SizeOfCode: 0x%x\n", optional_image.optional_64.sizeOfCode);
			fprintf(logfile, "\t+SizeOfInitializedData: 0x%x\n", optional_image.optional_64.sizeOfInitializedData);
			fprintf(logfile, "\t+SizeOfUnItializedData: 0x%x\n", optional_image.optional_64.sizeOfUnInitializedData);
			fprintf(logfile, "\t+AddressOfEntryPoint: 0x%x\n", optional_image.optional_64.addressOfEntryPoint);
			fprintf(logfile, "\t+BaseOfCode: 0x%x\n", optional_image.optional_64.baseOfCode);
			fprintf(logfile, "\t+ImageBase: 0x%x\n", (unsigned int)optional_image.optional_64.imageBase);
			fprintf(logfile, "\t+SectionAlignment: 0x%x\n", (unsigned int)optional_image.optional_64.sectionAlignment);
			fprintf(logfile, "\t+FileAlignment: 0x%x\n", optional_image.optional_64.fileAlignment);
			fprintf(logfile, "\t+MajorOperatingSystemVersion: 0x%x\n", optional_image.optional_64.majorOperatingSystemVersion);
			fprintf(logfile, "\t+MinorOperatingSystemVersion: 0x%x\n", optional_image.optional_64.minorOperatingSystemVersion);
			fprintf(logfile, "\t+MajorImageVersion: 0x%x\n", optional_image.optional_64.majorImageVersion);
			fprintf(logfile, "\t+MinorImageVersion: 0x%x\n", optional_image.optional_64.minorImageVersion);
			fprintf(logfile, "\t+MajorSubsystemVersion: 0x%x\n", optional_image.optional_64.majorSubsystemVersion);
			fprintf(logfile, "\t+MinorSubsystemVersion: 0x%x\n", optional_image.optional_64.minorSubsystemVersion);
			fprintf(logfile, "\t+Win32VersionValue: 0x%x\n", optional_image.optional_64.win32VersionValue);
			fprintf(logfile, "\t+SizeOfImage: 0x%x\n", optional_image.optional_64.sizeOfImage);
			fprintf(logfile, "\t+SizeOfHeaders: 0x%x\n", optional_image.optional_64.sizeOfHeaders);
			fprintf(logfile, "\t+Checksum: 0x%x\n", optional_image.optional_64.checkSum);
			fprintf(logfile, "\t+Subsystem: 0x%x\n", optional_image.optional_64.subsystem);
			fprintf(logfile, "\t+DllCharacteristics: 0x%x\n", optional_image.optional_64.dllCharacteristics);
			fprintf(logfile, "\t+SizeOfStackReserve: 0x%x\n", (unsigned int)optional_image.optional_64.sizeOfStackReserve);
			fprintf(logfile, "\t+SizeOfStackCommit: 0x%x\n", (unsigned int)optional_image.optional_64.sizeOfStackCommit);
			fprintf(logfile, "\t+SizeOfHeapReserve: 0x%x\n", (unsigned int)optional_image.optional_64.sizeOfHeapReserve);
			fprintf(logfile, "\t+SizeOfHeapCommit: 0x%x\n", (unsigned int)optional_image.optional_64.sizeOfHeapCommit);
			fprintf(logfile, "\t+LoaderFlags: 0x%x\n", optional_image.optional_64.loaderFlags);
			fprintf(logfile, "\t+NumberOfRvaAndSizes: 0x%x\n", optional_image.optional_64.numberOfRvaAndSizes);
		}
		else
		{
			fprintf(logfile, "\t+Magic: 0x%x\n", optional_image.optional_32.magic);
			fprintf(logfile, "\t+MajorLinkerVersion: 0x%x\n", optional_image.optional_32.majorLinkerVersion);
			fprintf(logfile, "\t+MenorLinkerVersion: 0x%x\n", optional_image.optional_32.minorLinkerVersion);
			fprintf(logfile, "\t+SizeOfCode: 0x%x\n", optional_image.optional_32.sizeOfCode);
			fprintf(logfile, "\t+SizeOfInitializedData: 0x%x\n", optional_image.optional_32.sizeOfInitializedData);
			fprintf(logfile, "\t+SizeOfUnItializedData: 0x%x\n", optional_image.optional_32.sizeOfUnInitializedData);
			fprintf(logfile, "\t+AddressOfEntryPoint: 0x%x\n", optional_image.optional_32.addressOfEntryPoint);
			fprintf(logfile, "\t+BaseOfCode: 0x%x\n", optional_image.optional_32.baseOfCode);
			fprintf(logfile, "\t+BaseOfData: 0x%x\n", optional_image.optional_32.baseOfData);
			fprintf(logfile, "\t+ImageBase: 0x%x\n", optional_image.optional_32.imageBase);
			fprintf(logfile, "\t+SectionAlignment: 0x%x\n", optional_image.optional_32.sectionAlignment);
			fprintf(logfile, "\t+FileAlignment: 0x%x\n", optional_image.optional_32.fileAlignment);
			fprintf(logfile, "\t+MajorOperatingSystemVersion: 0x%x\n", optional_image.optional_32.majorOperatingSystemVersion);
			fprintf(logfile, "\t+MinorOperatingSystemVersion: 0x%x\n", optional_image.optional_32.minorOperatingSystemVersion);
			fprintf(logfile, "\t+MajorImageVersion: 0x%x\n", optional_image.optional_32.majorImageVersion);
			fprintf(logfile, "\t+MinorImageVersion: 0x%x\n", optional_image.optional_32.minorImageVersion);
			fprintf(logfile, "\t+MajorSubsystemVersion: 0x%x\n", optional_image.optional_32.majorSubsystemVersion);
			fprintf(logfile, "\t+MinorSubsystemVersion: 0x%x\n", optional_image.optional_32.minorSubsystemVersion);
			fprintf(logfile, "\t+Win32VersionValue: 0x%x\n", optional_image.optional_32.win32VersionValue);
			fprintf(logfile, "\t+SizeOfImage: 0x%x\n", optional_image.optional_32.sizeOfImage);
			fprintf(logfile, "\t+SizeOfHeaders: 0x%x\n", optional_image.optional_32.sizeOfHeaders);
			fprintf(logfile, "\t+Checksum: 0x%x\n", optional_image.optional_32.checkSum);
			fprintf(logfile, "\t+Subsystem: 0x%x\n", optional_image.optional_32.subsystem);
			fprintf(logfile, "\t+DllCharacteristics: 0x%x\n", optional_image.optional_32.dllCharacteristics);
			fprintf(logfile, "\t+SizeOfStackReserve: 0x%x\n", optional_image.optional_32.sizeOfStackReserve);
			fprintf(logfile, "\t+SizeOfStackCommit: 0x%x\n", optional_image.optional_32.sizeOfStackCommit);
			fprintf(logfile, "\t+SizeOfHeapReserve: 0x%x\n", optional_image.optional_32.sizeOfHeapReserve);
			fprintf(logfile, "\t+SizeOfHeapCommit: 0x%x\n", optional_image.optional_32.sizeOfHeapCommit);
			fprintf(logfile, "\t+LoaderFlags: 0x%x\n", optional_image.optional_32.loaderFlags);
			fprintf(logfile, "\t+NumberOfRvaAndSizes: 0x%x\n", optional_image.optional_32.numberOfRvaAndSizes);
		}

		return true;
	}
}