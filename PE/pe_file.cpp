#include "pe_file.h"

/************* EXTERN VARIABLES *************/
extern FILE* logfile;

pe_file::pe_file(ADDRINT binary_address)
{
	this->binary_is_okay		= true;
	this->binary_img			= IMG_FindByAddress(binary_address);

	if (this->binary_img == IMG_Invalid())
	{
		this->binary_is_okay = false;
		return;
	}

	this->binary_base_address	= IMG_StartAddress(this->binary_img);

	if (this->binary_base_address == NULL)
	{
		this->binary_is_okay = false;
		return;
	}

	fprintf(stderr,  "[INFO] PE file base address: 0x%x\n", (uintptr_t)this->binary_base_address);
	fprintf(logfile, "[INFO] PE file base address: 0x%x\n", (uintptr_t)this->binary_base_address);
}

pe_file::pe_file(IMG binary_img)
{
	this->binary_is_okay		= true;
	this->binary_img			= binary_img;

	if (this->binary_img == IMG_Invalid())
	{
		this->binary_is_okay = false;
		return;
	}

	this->binary_base_address = IMG_StartAddress(this->binary_img);

	if (this->binary_base_address == NULL)
	{
		this->binary_is_okay = false;
		return;
	}

	fprintf(stderr, "[INFO] PE file base address: 0x%x\n", (uintptr_t)this->binary_base_address);
	fprintf(logfile, "[INFO] PE file base address: 0x%x\n", (uintptr_t)this->binary_base_address);
}

pe_file::~pe_file()
{
	if (this->initial_entropies != nullptr)
	{
		free(this->initial_entropies);
	}

	if (this->dos_header != nullptr)
	{
		delete this->dos_header;
	}

	if (this->dos_stub != nullptr)
	{
		free(this->dos_stub);
	}

	if (this->nt_coff_header != nullptr)
	{
		delete this->nt_coff_header;
	}

	if (this->optional_header != nullptr)
	{
		delete this->optional_header;
	}

	if (this->data_directory_header != nullptr)
	{
		delete this->data_directory_header;
	}

	if (this->section_table_header != nullptr)
	{
		delete this->section_table_header;
	}
}

bool pe_file::analyze_binary()
{
	if (parse_pe_header())
		if (calculate_initial_entropy())
			return true;
	return false;
}

bool pe_file::has_section_changed_entropy(ADDRINT address_of_section)
{
	size_t i;
	float entropy;
	float threshold;
	pe_parser::section_header_t::section_struct_t* section = this->section_table_header->get_section_by_rva((uint64_t)(address_of_section - this->binary_base_address));

	if (section == nullptr)
		return false;

	entropy = calculate_entropy_section(*section);

	for (i = 0; i < this->number_of_sections; i++)
	{
		if (this->section_table_header->get_sections().at(i).virtualAddress == section->virtualAddress)
		{
			threshold = this->initial_entropies[i] * (this->entropy_threshold / 100.0);
			if (
				(entropy > this->initial_entropies[i] + threshold) || 
				(entropy < this->initial_entropies[i] - threshold)
				)
			{
				fprintf(stderr, "[INFO] Section with Virtual Address 0x%x has changed entropy from %f to %f\n", this->section_table_header->get_sections().at(i).virtualAddress, this->initial_entropies[i], entropy);
				fprintf(logfile, "[INFO] Section with Virtual Address 0x%x has changed entropy from %f to %f\n", this->section_table_header->get_sections().at(i).virtualAddress, this->initial_entropies[i], entropy);
				return true;
			}
			else
				return false;
		}
	}

	return true;
}

bool pe_file::on_pe_file(ADDRINT address)
{
	if (!this->binary_is_okay)
		return false;

	address -= binary_base_address;


	if (optional_header->is_64_bit_binary())
	{
		if (binary_base_address + optional_header->get_optional_image().optional_64.sizeOfImage >= address)
			return true;
	}
	else
	{
		if (binary_base_address + optional_header->get_optional_image().optional_32.sizeOfImage >= address)
			return true;
	}

	return false;
}

float pe_file::calculate_entropy_section(pe_parser::section_header_t::section_struct_t section)
{
	float		count						= 0.0;
	float		entropy						= 0.0;
	uint32_t	each_byte_repetition[256]	= { 0 };
	uint8_t*	buffer_for_section			= nullptr;
	uint8_t		aux;
	size_t		i;
	buffer_for_section = (uint8_t*)calloc(section.virtualSize, sizeof(uint8_t));

	for (i = 0; i < section.virtualSize; i++)
	{
		if (PIN_SafeCopy(
			(VOID*)(&aux),
			(const VOID*)(this->binary_base_address + (ADDRINT)section.virtualAddress + (ADDRINT)i),
			sizeof(uint8_t)
		) != sizeof(uint8_t))
			std::__stl_throw_runtime_error("[ERROR] Reading byte from memory");

		each_byte_repetition[aux]++;
	}

	for (i = 0; i <= 0xff; i++)
	{
		if (each_byte_repetition[i] != 0)
		{
			count = (float)each_byte_repetition[i] / (float)section.virtualSize;
			entropy += -count * log2f(count);
		}
	}

	free(buffer_for_section);

	return entropy;
}

bool pe_file::calculate_initial_entropy()
{
	size_t i;
	
	this->initial_entropies = (float*)calloc(this->number_of_sections, sizeof(float));

	for (i = 0; i < this->number_of_sections; i++)
	{
		initial_entropies[i] = calculate_entropy_section(this->section_table_header->get_sections().at(i));

		fprintf(stderr, "[INFO] Entropy for section in RVA 0x%x - %f\n", this->section_table_header->get_sections().at(i).virtualAddress, initial_entropies[i]);
		fprintf(logfile, "[INFO] Entropy for section in RVA 0x%x - %f\n", this->section_table_header->get_sections().at(i).virtualAddress, initial_entropies[i]);
	}
	
	return true;
}

bool pe_file::parse_pe_header()
{
	if (!this->binary_is_okay)
		return false;

	ADDRINT address = this->binary_base_address;
	headers_are_correct = false;

	if (!parse_and_check_dos_header(address))
	{
		fprintf(stderr, "[ERROR] dos header not correct\n");
		fprintf(logfile, "[ERROR] dos header not correct\n");
		return headers_are_correct;
	}

	// the address of the dos stub will be the base + size of header
	address += sizeof(pe_parser::dos_header_t::dos_header_struct_t);

	if (!read_dos_stub(address))
	{
		fprintf(stderr, "[ERROR] dos stub not correct\n");
		fprintf(logfile, "[ERROR] dos stub not correct\n");
		return headers_are_correct;
	}

	// address of nt header, will be the last one plus 
	// the difference between the offset e_lfanew and
	// the size of dos struct.
	address += (dos_header->get_dos_header().e_lfanew -
		sizeof(pe_parser::dos_header_t::dos_header_struct_t));

	if (!parse_and_check_nt_header(address))
	{
		fprintf(stderr, "[ERROR] nt header not correct\n");
		fprintf(logfile, "[ERROR] nt header not correct\n");
		return headers_are_correct;
	}

	address += sizeof(pe_parser::nt_header_t::nt_coff_struct_t);

	if (!parse_and_check_optional_header(address))
	{
		fprintf(stderr, "[ERROR] optional header not correct\n");
		fprintf(logfile, "[ERROR] optional header not correct\n");
		return headers_are_correct;
	}

	// to get the next address it will be necessary
	// to check if process is 32 or 64 binary.
	if (optional_header->is_64_bit_binary())
		address += sizeof(pe_parser::optional_header_t::optional_image_only_p64_t);
	else
		address += sizeof(pe_parser::optional_header_t::optional_image_only_p32_t);

	if (!parse_and_check_data_directories(address))
	{
		fprintf(stderr, "[ERROR] data directories not correct");
		fprintf(logfile, "[ERROR] data directories not correct");
		return headers_are_correct;
	}

	if (optional_header->is_64_bit_binary())
		address += optional_header->get_optional_image().optional_64.numberOfRvaAndSizes * sizeof(pe_parser::data_directory_header_t::data_directory_struct_t);
	else
		address += optional_header->get_optional_image().optional_32.numberOfRvaAndSizes * sizeof(pe_parser::data_directory_header_t::data_directory_struct_t);

	if (!parse_and_check_section_headers(address))
	{
		fprintf(stderr, "[ERROR] section headers not correct");
		fprintf(logfile, "[ERROR] section headers not correct");
		return headers_are_correct;
	}


	this->number_of_sections = this->nt_coff_header->get_nt_header().numberOfSections;

	headers_are_correct = true;

	return true;
}

bool pe_file::entropy_higher_than_HE(uint32_t entropy)
{
	return true;
}

bool pe_file::entropy_lower_than_LE(uint32_t entropy)
{
	return true;
}

bool pe_file::parse_and_check_dos_header(ADDRINT address)
{
	dos_header = new pe_parser::dos_header_t(address);

	dos_header->dump_dos_header();

	return dos_header->check_dos_header();
}

bool pe_file::read_dos_stub(ADDRINT address)
{
	// dos stub is not mandatory
	if (sizeof(pe_parser::dos_header_t::dos_header_struct_t) > dos_header->get_dos_header().e_lfanew)
		return true;

	size_t copied_size, size_to_copy = (dos_header->get_dos_header().e_lfanew -
		sizeof(pe_parser::dos_header_t::dos_header_struct_t));
	dos_stub = (uint8_t*)calloc(size_to_copy, sizeof(uint8_t));

	copied_size = PIN_SafeCopy((VOID*)dos_stub, (const VOID*)address, size_to_copy);

	return copied_size == size_to_copy;
}

bool pe_file::parse_and_check_nt_header(ADDRINT address)
{
	nt_coff_header = new pe_parser::nt_header_t(address);

	nt_coff_header->dump_nt_header();

	return nt_coff_header->is_pe_header_correct();
}

bool pe_file::parse_and_check_optional_header(ADDRINT address)
{
	optional_header = new pe_parser::optional_header_t(address);

	optional_header->dump_optional_image();

	return optional_header->is_optional_header_correct();
}

bool pe_file::parse_and_check_data_directories(ADDRINT address)
{
	if (optional_header->is_64_bit_binary())
		data_directory_header = new pe_parser::data_directory_header_t(address,
			optional_header->get_optional_image().optional_64.numberOfRvaAndSizes,
			optional_header->get_optional_image().optional_64.sizeOfImage);
	else
		data_directory_header = new pe_parser::data_directory_header_t(address,
			optional_header->get_optional_image().optional_32.numberOfRvaAndSizes,
			optional_header->get_optional_image().optional_32.sizeOfImage);

	data_directory_header->dump_directories();

	return data_directory_header->is_data_directory_correct();
}

bool pe_file::parse_and_check_section_headers(ADDRINT address)
{
	if (optional_header->is_64_bit_binary())
		section_table_header = new pe_parser::section_header_t(address,
			nt_coff_header->get_nt_header().numberOfSections,
			optional_header->get_optional_image().optional_64.sizeOfImage);
	else
		section_table_header = new pe_parser::section_header_t(address,
			nt_coff_header->get_nt_header().numberOfSections,
			optional_header->get_optional_image().optional_32.sizeOfImage);

	section_table_header->dump_sections();

	return section_table_header->are_sections_correct();
}