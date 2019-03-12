
#include "section_header.h"

/************* EXTERN VARIABLES *************/
extern FILE *logfile; // log file handler


namespace pe_parser
{
	section_header_t::section_header_t(ADDRINT address, uint32_t number_of_sections, uint32_t size_of_image)
	{
		size_t copied_size, size_to_copy = sizeof(section_struct_t);
		size_t i;
		section_struct_t section_aux;
		sections_are_correct = true;
		this->number_of_sections = number_of_sections;
		
		for (i = 0; i < number_of_sections; i++)
		{
			copied_size = PIN_SafeCopy((VOID*)&section_aux, (VOID*)(address + (i * size_to_copy)), size_to_copy);
			
			if (copied_size != size_to_copy)
			{
				sections_are_correct = false;
				return;
			}
			
			if (section_aux.virtualAddress > size_of_image ||
				(section_aux.virtualAddress + section_aux.virtualSize) > size_of_image)
			{
				sections_are_correct = false;
				return;
			}

			sections.push_back(section_aux);
		}	
	}

	std::vector<section_header_t::section_struct_t>& section_header_t::get_sections()
	{
		return sections;
	}

	section_header_t::section_struct_t* section_header_t::get_section_by_rva(uint64_t rva)
	{
		size_t i;

		for (i = 0; i < sections.size(); i++)
		{
			if (rva >= sections[i].virtualAddress ||
				rva < (sections[i].virtualAddress + sections[i].virtualSize))
			{
				return &sections[i];
			}
		}
		return nullptr;
	}

	section_header_t::section_struct_t* section_header_t::get_section_by_offset(uint64_t offset)
	{
		size_t i;

		for (i = 0; i < sections.size(); i++)
		{
			if (offset >= sections[i].pointerToRawData ||
				offset < (sections[i].pointerToRawData + sections[i].sizeOfRawData))
			{
				return &sections[i];
			}
		}
		return nullptr;
	}

	bool section_header_t::dump_sections()
	{
		size_t i;
		string name;
		if (!sections_are_correct)
			return false;

		fprintf(logfile, "================== DUMP SECTION HEADERS ===================\n");
		for (i = 0; i < number_of_sections; i++)
		{
			name = "";
			for (size_t j = 0; j < 8; j++)
				name += sections[i].name[j];
			fprintf(logfile, "\t+Name: %s\n", name.c_str());
			fprintf(logfile, "\t+Virtual Size: 0x%x\n", sections[i].virtualSize);
			fprintf(logfile, "\t+Virtual Address: 0x%x\n", sections[i].virtualAddress);
			fprintf(logfile, "\t+Pointer to Raw Data: 0x%x\n", sections[i].pointerToRawData);
			fprintf(logfile, "\t+Size of Raw Data: 0x%x\n", sections[i].sizeOfRawData);
			fprintf(logfile, "\t+Pointer to relocations: 0x%x\n", sections[i].pointerToRelocations);
			fprintf(logfile, "\t+Pointer to line numbers: 0x%x\n", sections[i].pointerToLineNumbers);
			fprintf(logfile, "\t+Number of relocations: 0x%x\n", sections[i].numberOfRelocations);
			fprintf(logfile, "\t+Number of line numbers: 0x%x\n", sections[i].numberOfLineNumbers);
			fprintf(logfile, "\t+Characteristics: 0x%x\n", sections[i].characteristics);
		}

		return true;
	}

	bool section_header_t::are_sections_correct()
	{
		return sections_are_correct;
	}
}