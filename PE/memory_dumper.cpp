
#include "memory_dumper.h"

extern FILE* logfile;

memory_dumper_t::memory_dumper_t(ADDRINT indirect_jump_target) : dos_header(nullptr),
																 nt_coff_header(nullptr),
																 data_directory_header(nullptr),
																 section_table_header(nullptr),
																 dos_stub(nullptr),
																 dump_correct(false),
																 headers_correct(false)
/***
*	Constructor for unpacker when file has been dumped
*	from the same memory and then there's an indirect
*	jump to the unpacked code.
*/
{
	this->address_code_to_dump = indirect_jump_target;
	img_to_dump = IMG_FindByAddress(indirect_jump_target);

	base_address_to_dump = IMG_StartAddress(img_to_dump);

	this->address_code_to_dump -= base_address_to_dump;

	fprintf(stderr,		"[INFO] Address of code to dump: 0x%x\n", (uintptr_t)indirect_jump_target);
	fprintf(logfile,	"[INFO] Address of code to dump: 0x%x\n", (uintptr_t)indirect_jump_target);
	fprintf(stderr,		"[INFO] Base address of that image: 0x%x\n", (uintptr_t)base_address_to_dump);
	fprintf(logfile,	"[INFO] Base address of that image: 0x%x\n", (uintptr_t)base_address_to_dump);
}

memory_dumper_t::memory_dumper_t(std::vector<uint8_t> file_base_in_vector) : dos_header(nullptr),
																					nt_coff_header(nullptr),
																					data_directory_header(nullptr),
																					section_table_header(nullptr),
																					dos_stub(nullptr),
																					dump_correct(false),
																					headers_correct(false)
/***
*	Constructor for the unpacker when unpacks a RunPE
*	we have the file in vectors of bytes, as it will 
*	be better that than not reading the code from the
*	other process.
*/
{
	this->data_from_vector = file_base_in_vector;
	this->address_code_to_dump = 0;
	base_address_to_dump = (ADDRINT) this->data_from_vector.begin();

	fprintf(stderr, "[INFO] Base address of that image: 0x%x\n", (uintptr_t)base_address_to_dump);
	fprintf(logfile, "[INFO] Base address of that image: 0x%x\n", (uintptr_t)base_address_to_dump);
}

memory_dumper_t::~memory_dumper_t()
{
	if (dumped_file != NULL)
		fclose(dumped_file);

	if (dos_header != nullptr)
		delete dos_header;

	if (nt_coff_header != nullptr)
		delete nt_coff_header;

	if (data_directory_header != nullptr)
		delete data_directory_header;

	if (section_table_header != nullptr)
		delete section_table_header;

	if (dos_stub != nullptr)
		free(dos_stub);

	if (data_from_vector.size() != 0)
		data_from_vector.empty();
}

bool memory_dumper_t::parse_memory()
/***
*	Parse the PE header from memory, check also
*	if everything is correct.
*/
{
	ADDRINT address = base_address_to_dump;
	headers_correct = false;

	fprintf(stderr, "[INFO] Address of dos header: 0x%x\n", address);
	fprintf(logfile,"[INFO] Address of dos header: 0x%x\n", address);
	if (!parse_and_check_dos_header(address))
	{
		fprintf(stderr, "[ERROR] dos header not correct\n");
		fprintf(logfile, "[ERROR] dos header not correct\n");
		return headers_correct;
	}

	// the address of the dos stub will be the base + size of header
	address += sizeof(pe_parser::dos_header_t::dos_header_struct_t);

	fprintf(stderr, "[INFO] Address of dos stub: 0x%x\n", address);
	fprintf(logfile, "[INFO] Address of dos stub: 0x%x\n", address);

	if (!read_dos_stub(address))
	{
		fprintf(stderr, "[ERROR] dos stub not correct\n");
		fprintf(logfile, "[ERROR] dos stub not correct\n");
		return headers_correct;
	}

	// address of nt header, will be the last one plus 
	// the difference between the offset e_lfanew and
	// the size of dos struct.
	address += (dos_header->get_dos_header().e_lfanew -
		sizeof(pe_parser::dos_header_t::dos_header_struct_t));

	fprintf(stderr, "[INFO] Address of nt header: 0x%x\n", address);
	fprintf(logfile, "[INFO] Address of nt header: 0x%x\n", address);

	if (!parse_and_check_nt_header(address))
	{
		fprintf(stderr, "[ERROR] nt header not correct\n");
		fprintf(logfile, "[ERROR] nt header not correct\n");
		return headers_correct;
	}
	
	address += sizeof(pe_parser::nt_header_t::nt_coff_struct_t);


	fprintf(stderr, "[INFO] Address of optional header: 0x%x\n", address);
	fprintf(logfile, "[INFO] Address of optional header: 0x%x\n", address);
	if (!parse_and_check_optional_header(address))
	{
		fprintf(stderr, "[ERROR] optional header not correct\n");
		fprintf(logfile, "[ERROR] optional header not correct\n");
		return headers_correct;
	}

	// to get the next address it will be necessary
	// to check if process is 32 or 64 binary.
	if (optional_header->is_64_bit_binary())
		address += sizeof(pe_parser::optional_header_t::optional_image_only_p64_t);
	else
		address += sizeof(pe_parser::optional_header_t::optional_image_only_p32_t);

	fprintf(stderr, "[INFO] Address of data directories: 0x%x\n", address);
	fprintf(logfile, "[INFO] Address of data directories: 0x%x\n", address);
	if (!parse_and_check_data_directories(address))
	{
		fprintf(stderr, "[ERROR] data directories not correct");
		fprintf(logfile, "[ERROR] data directories not correct");
		return headers_correct;
	}
	if (optional_header->is_64_bit_binary())
		address += optional_header->get_optional_image().optional_64.numberOfRvaAndSizes * sizeof(pe_parser::data_directory_header_t::data_directory_struct_t);
	else
		address += optional_header->get_optional_image().optional_32.numberOfRvaAndSizes * sizeof(pe_parser::data_directory_header_t::data_directory_struct_t);
	
	fprintf(stderr, "[INFO] Address of section headers: 0x%x\n", address);
	fprintf(logfile, "[INFO] Address of section headers: 0x%x\n", address);
	if (!parse_and_check_section_headers(address))
	{
		fprintf(stderr, "[ERROR] section headers not correct");
		fprintf(logfile, "[ERROR] section headers not correct");
		return headers_correct;
	}
	headers_correct = true;

	importer = new Importer(dos_header, nt_coff_header, optional_header, data_directory_header, section_table_header);

	return headers_correct;
}

bool memory_dumper_t::dump_pe_to_file()
/***
*	Function to dump the file when it has been
*	unpacked in the same memory. 
*/
{
	if (!headers_correct)
		return false;

	snprintf(file_name, sizeof(file_name) - 1, "file.base-0x%x.entry-0x%x.bin", (uintptr_t)base_address_to_dump
, (uintptr_t)address_code_to_dump);

	dumped_file = fopen(file_name, "wb");

	if (!dumped_file)
		return false;

	// first re-align pe header, can reduce size of file.
	realign_pe();
	fprintf(stderr, "[INFO] PE realigned\n");
	fprintf(logfile, "[INFO] PE realigned\n");

	// set the new entry point, as the one from the header
	// will be packer's entry point.
	if (optional_header->is_64_bit_binary())
		optional_header->get_optional_image().optional_64.addressOfEntryPoint = (uint32_t) address_code_to_dump;
	else
		optional_header->get_optional_image().optional_32.addressOfEntryPoint = (uint32_t) address_code_to_dump;

	// first write the headers to the file
	if (!write_headers_to_file())
		return false;
	// finally write section by section
	if (!write_sections_to_file())
		return false;

	std::vector<uint8_t> import_section = importer->ImporterDumpToFile(data_directory_header->get_data_directories().at(data_directory_header->import_table_k).virtualAddress);

	create_new_section(import_section, section_table_header->IMAGE_SCN_CNT_INITIALIZED_DATA_k |
		section_table_header->IMAGE_SCN_MEM_READ_k | section_table_header->IMAGE_SCN_MEM_WRITE_k, ".F9");

	uint32_t first_thunk = importer->get_rva_first_thunk();
	
	auto* section = section_table_header->get_section_by_rva(first_thunk);

	section->characteristics |= section_table_header->IMAGE_SCN_MEM_WRITE_k;
	section->characteristics |= section_table_header->IMAGE_SCN_MEM_READ_k;

	fprintf(stderr, "[INFO] Written new import table into the raw pointer: 0x%x\n",
		section_table_header->get_sections().at(
			section_table_header->get_sections().size() - 1).pointerToRawData);

	fseek(dumped_file,
		section_table_header->get_sections().at(
			section_table_header->get_sections().size() - 1).pointerToRawData,
		SEEK_SET
	);

	size_t written_bytes = fwrite(import_section.begin(), import_section.size(), 1, dumped_file);

	if (!written_bytes)
		return false;

	// write again the headers
	if (!write_headers_to_file())
		return false;

	return true;
}

bool memory_dumper_t::dump_runpe_to_file(std::vector<write_memory_t> file_data, ADDRINT base_address)
/***
*	Dumper for the RunPE, it will use vector with 
*	the possible sections, also we give a base
*	address to create the name of the file.
*/
{
	ADDRINT image_base;
	size_t written_bytes;
	std::vector<pe_parser::section_header_t::section_struct_t> sections;
	size_t index_section = -1;
	size_t size_to_copy;

	if (!headers_correct)
		return false;

	snprintf(file_name, sizeof(file_name) - 1, "file_run_pe.base-0x%x.bin", (uintptr_t)base_address);

	dumped_file = fopen(file_name,"wb");

	if (!dumped_file)
		return false;

	// get the image base for later
	if (optional_header->is_64_bit_binary())
	{
		image_base = (ADDRINT)optional_header->get_optional_image().optional_64.imageBase;
	}
	else
	{
		image_base = optional_header->get_optional_image().optional_32.imageBase;
	}

	// write headers to file (as we have the header on structs).
	if (!write_headers_to_file())
		return false;
	// get the structure of sections
	sections = section_table_header->get_sections();
	
	for (size_t j = 0; j < sections.size(); j++)
	{
		index_section = -1;

		fprintf(stderr, "[INFO] Trying to dump the section with RVA 0x%x and raw size 0x%x\n", 
			sections.at(j).virtualAddress, sections.at(j).sizeOfRawData);
		fprintf(logfile, "[INFO] Trying to dump the section with RVA 0x%x and raw size 0x%x\n",
			sections.at(j).virtualAddress, sections.at(j).sizeOfRawData);

		for (size_t i = 0; i < file_data.size(); i++)
		{
			// search inside of the vectors for the virtual address
			// of each section.
			if (sections.at(j).virtualAddress == (file_data.at(i).address - image_base))
			{
				index_section = i;
				break;
			}
		}
		// if the vector does not contain the section
		// it is an error, is not possible to dump.
		if (index_section == -1)
			return false;

		if (fseek(dumped_file, sections.at(j).pointerToRawData, SEEK_SET))
			return false;

		size_to_copy = MIN(sections.at(j).sizeOfRawData, file_data.at(index_section).data.size());
		written_bytes = fwrite(file_data.at(index_section).data.begin(), size_to_copy, 1, dumped_file);

		if (!written_bytes)
			return false;
	}
	
	return true;
}

uint64_t memory_dumper_t::rva_to_offset(uint64_t rva)
{
	uint32_t section_alignment, file_alignment;

	if (optional_header->is_64_bit_binary())
	{
		section_alignment = optional_header->get_optional_image().optional_64.sectionAlignment;
		file_alignment = optional_header->get_optional_image().optional_64.fileAlignment;
	}
	else
	{
		section_alignment = optional_header->get_optional_image().optional_32.sectionAlignment;
		file_alignment = optional_header->get_optional_image().optional_32.fileAlignment;
	}

	pe_parser::section_header_t::section_struct_t *section = section_table_header->get_section_by_rva(rva);

	if (section == nullptr)
		return rva;

	if (section_alignment < 0x1000)
	{
		section_alignment = file_alignment;
	}

	uint64_t section_rva = section->virtualAddress;
	uint64_t section_offset = section->pointerToRawData;

	return ((rva - section_rva) + section_offset);
}

uint64_t memory_dumper_t::offset_to_rva(uint64_t offset)
{
	uint32_t section_alignment, file_alignment;

	if (optional_header->is_64_bit_binary())
	{
		section_alignment = optional_header->get_optional_image().optional_64.sectionAlignment;
		file_alignment = optional_header->get_optional_image().optional_64.fileAlignment;
	}
	else
	{
		section_alignment = optional_header->get_optional_image().optional_32.sectionAlignment;
		file_alignment = optional_header->get_optional_image().optional_32.fileAlignment;
	}

	pe_parser::section_header_t::section_struct_t *section = section_table_header->get_section_by_offset(offset);

	if (section == nullptr)
		return offset;

	uint64_t section_offset = section->pointerToRawData;
	uint64_t section_rva = section->virtualAddress;

	return ((offset - section_offset) + section_rva);
}

pe_parser::data_directory_header_t*	memory_dumper_t::get_data_directories()
{
	return data_directory_header;
}

pe_parser::section_header_t* memory_dumper_t::get_section_table_header()
{
	return section_table_header;
}

Importer* memory_dumper_t::get_importer()
{
	return importer;
}
/************** PRIVATE METHODS **********************/
bool memory_dumper_t::parse_and_check_dos_header(ADDRINT address)
/***
*	Use the dos header class to parse the dos header
*/
{
	dos_header = new pe_parser::dos_header_t(address);

	dos_header->dump_dos_header();

	return dos_header->check_dos_header();
}

bool memory_dumper_t::read_dos_stub(ADDRINT address)
/***
*	Read the dos stub
*/
{
	size_t copied_size, size_to_copy = (dos_header->get_dos_header().e_lfanew -
											sizeof(pe_parser::dos_header_t::dos_header_struct_t));
	dos_stub = (uint8_t*) malloc(size_to_copy);

	copied_size = PIN_SafeCopy((VOID*)dos_stub, (const VOID*)address, size_to_copy);

	return copied_size == size_to_copy;
}

bool memory_dumper_t::parse_and_check_nt_header(ADDRINT address)
/***
*	Use nt class to parse nt header
*/
{
	nt_coff_header = new pe_parser::nt_header_t(address);

	nt_coff_header->dump_nt_header();

	return nt_coff_header->is_pe_header_correct();
}

bool memory_dumper_t::parse_and_check_optional_header(ADDRINT address)
/***
*	Use optional header class to parse the optional header
*/
{
	optional_header = new pe_parser::optional_header_t(address);

	optional_header->dump_optional_image();

	return optional_header->is_optional_header_correct();
}

bool memory_dumper_t::parse_and_check_data_directories(ADDRINT address)
/***
*	Read data directories
*/
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

bool memory_dumper_t::parse_and_check_section_headers(ADDRINT address)
/***
*	Read the section headers
*/
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

bool memory_dumper_t::check_import_directory()
{
	return data_directory_header->get_data_directories().at(pe_parser::data_directory_header_t::import_table_k).virtualAddress != 0;
}

bool memory_dumper_t::check_export_directory()
{
	return data_directory_header->get_data_directories().at(pe_parser::data_directory_header_t::export_table_k).virtualAddress != 0;
}

bool memory_dumper_t::check_relocation_directory()
{
	return data_directory_header->get_data_directories().at(pe_parser::data_directory_header_t::base_relocation_table_k).virtualAddress != 0;
}

uint32_t memory_dumper_t::calc_correct_size_of_headers()
{
	uint32_t correct_size = dos_header->get_dos_header().e_lfanew + 50;

	correct_size += sizeof(pe_parser::nt_header_t::nt_coff_struct_t);

	if (optional_header->is_64_bit_binary())
	{
		correct_size += sizeof(pe_parser::optional_header_t::optional_image_only_p64_t);
		correct_size += sizeof(pe_parser::data_directory_header_t::data_directory_struct_t) * optional_header->get_optional_image().optional_64.numberOfRvaAndSizes;
	}
	else
	{
		correct_size += sizeof(pe_parser::optional_header_t::optional_image_only_p32_t);
		correct_size += sizeof(pe_parser::data_directory_header_t::data_directory_struct_t) * optional_header->get_optional_image().optional_32.numberOfRvaAndSizes;
	}


	correct_size += sizeof(pe_parser::section_header_t::section_struct_t) * nt_coff_header->get_nt_header().numberOfSections;
	
	return correct_size;
}

bool memory_dumper_t::create_new_section(std::vector<uint8_t> buffer, uint32_t characteristics, const char *name)
{
	pe_parser::section_header_t::section_struct_t	new_section = { 0 };
	uint32_t NewVirtualSection = 0;
	uint32_t NewSectionRawPointer = 0;
	uint32_t SectionDataPtr = 0;
	uint32_t SectionVirtualSize = 0;
	uint32_t new_size_of_image;
	uint32_t section_alignment;
	uint32_t file_alignment;

	if (optional_header->is_64_bit_binary())
	{
		section_alignment = optional_header->get_optional_image().optional_64.sectionAlignment;
		file_alignment = optional_header->get_optional_image().optional_64.fileAlignment;
	}
	else
	{
		section_alignment = optional_header->get_optional_image().optional_32.sectionAlignment;
		file_alignment = optional_header->get_optional_image().optional_32.fileAlignment;
	}

	auto sections = section_table_header->get_sections();
	auto last_section = sections.at(sections.size() - 1);

	// align last size of raw data
	SectionDataPtr = last_section.sizeOfRawData;
	SectionDataPtr = (SectionDataPtr / file_alignment) * file_alignment;

	NewSectionRawPointer = last_section.pointerToRawData + SectionDataPtr;

	// align last SectionVirtualSize
	SectionVirtualSize = last_section.virtualSize;
	if ((SectionVirtualSize % section_alignment) > 0)
		SectionVirtualSize = SectionVirtualSize + (section_alignment - (SectionVirtualSize % section_alignment));

	NewVirtualSection = last_section.virtualAddress + SectionVirtualSize;

	// Set values for new section
	strncpy(reinterpret_cast<char *>(new_section.name), name, 8);
	new_section.characteristics = characteristics;
	new_section.pointerToRawData = NewSectionRawPointer;
	new_section.sizeOfRawData = (uint32_t)buffer.size();
	new_section.virtualAddress = NewVirtualSection;
	new_section.virtualSize = (uint32_t)buffer.size();

	// now increase size of image
	new_size_of_image = new_section.virtualAddress + new_section.virtualSize;
	if ((new_size_of_image % section_alignment) > 0)
		new_size_of_image = new_size_of_image + (section_alignment - (new_size_of_image % section_alignment));

	section_table_header->get_sections().push_back(new_section);
	
	nt_coff_header->get_nt_header().numberOfSections += 1;
	
	if (optional_header->is_64_bit_binary())
		optional_header->get_optional_image().optional_64.sizeOfImage = new_size_of_image;
	else
		optional_header->get_optional_image().optional_32.sizeOfImage = new_size_of_image;

	return true;
}
/************** PRIVATE DUMP FUNCTIONS **********************/
uint64_t memory_dumper_t::realign_pe()
{
	uint32_t new_virtual_section_size	= 0;
	uint32_t new_section_raw_pointer	= 0;
	uint32_t old_section_data_raw_ptr	= 0;
	uint32_t old_section_data_ptr		= 0;
	uint32_t section_data_ptr			= 0;
	uint32_t current_section			= 0;
	uint32_t file_alignment				= 0;
	uint8_t  aux;

	auto& section_vector = section_table_header->get_sections();

	if (optional_header->is_64_bit_binary())
		file_alignment = optional_header->get_optional_image().optional_64.fileAlignment;
	else
		file_alignment = optional_header->get_optional_image().optional_32.fileAlignment;

	if (file_alignment == 0x1000)
		file_alignment = 0x200;

	if (optional_header->is_64_bit_binary())
		optional_header->get_optional_image().optional_64.fileAlignment = file_alignment;
	else
		optional_header->get_optional_image().optional_32.fileAlignment = file_alignment;

	for (size_t i = 0; i < section_vector.size(); i++)
	{
		auto &sec = section_vector[i];
		section_data_ptr =  sec.virtualAddress + sec.sizeOfRawData;

		if (sec.sizeOfRawData > 0)
		{
			section_data_ptr--;
			PIN_SafeCopy((VOID*)&aux, (const VOID*)section_data_ptr, 1);

			while (aux == 0 && section_data_ptr > sec.virtualAddress)
			{
				section_data_ptr--;
				PIN_SafeCopy((VOID*)&aux, (const VOID*)(base_address_to_dump + section_data_ptr), 1);
			}
		}

		section_data_ptr		= section_data_ptr - sec.virtualAddress;
		old_section_data_ptr	= section_data_ptr;
		section_data_ptr		= (section_data_ptr / file_alignment) * file_alignment;

		if (section_data_ptr < old_section_data_ptr)
			section_data_ptr = section_data_ptr + file_alignment;

		if (current_section == 0)
		{
			if (optional_header->is_64_bit_binary())
			{
				optional_header->get_optional_image().optional_64.sizeOfHeaders = sec.pointerToRawData;
				optional_header->get_optional_image().optional_64.sectionAlignment = sec.virtualAddress;
			}
			else
			{
				optional_header->get_optional_image().optional_32.sizeOfHeaders = sec.virtualAddress;
				optional_header->get_optional_image().optional_32.sectionAlignment = sec.virtualAddress;
			}
			sec.sizeOfRawData = section_data_ptr;
		}
		else
		{
			old_section_data_ptr	= sec.pointerToRawData;
			sec.sizeOfRawData		= section_data_ptr;
			new_section_raw_pointer	= section_vector[i - 1].pointerToRawData + section_vector[i - 1].sizeOfRawData;
			section_vector[i].pointerToRawData = new_section_raw_pointer;
		}
		
		if (new_virtual_section_size < sec.virtualSize)
		{
			if (optional_header->is_64_bit_binary())
				new_virtual_section_size = new_virtual_section_size + optional_header->get_optional_image().optional_64.sectionAlignment;
			else
				new_virtual_section_size = new_virtual_section_size + optional_header->get_optional_image().optional_32.sectionAlignment;
		}

		sec.virtualSize = new_virtual_section_size;

		if (i != (section_vector.size() - 1))
		{
			if ((sec.virtualSize + sec.virtualAddress) < section_vector[i + 1].virtualAddress)
			{
				sec.virtualSize = section_vector[i + 1].virtualAddress - sec.virtualAddress;
			}
		}

		current_section++;
	}

	return section_vector[section_vector.size() - 1].pointerToRawData +
		section_vector[section_vector.size() - 1].sizeOfRawData;
}

bool memory_dumper_t::write_headers_to_file()
{
	size_t written_bytes, i;

	fseek(dumped_file, 0, SEEK_SET);

	fprintf(stderr, "[INFO] Writing to file dos header\n");
	fprintf(logfile, "[INFO] Writing to file dos header\n");
	written_bytes = fwrite(&dos_header->get_dos_header(), sizeof(dos_header->get_dos_header()), 1, dumped_file);

	if (!written_bytes)
	{
		fprintf(stderr, "[ERROR] not possible to write dos header\n");
		fprintf(logfile, "[ERROR] not possible to write dos header\n");
		return false;
	}

	fprintf(stderr, "[INFO] Writing to file dos stub\n");
	fprintf(logfile, "[INFO] Writing to file dos stub\n");
	written_bytes = fwrite(dos_stub, (dos_header->get_dos_header().e_lfanew - sizeof(dos_header->get_dos_header())), 1, dumped_file);

	if (!written_bytes)
	{
		fprintf(stderr, "[ERROR] not possible to write dos stub\n");
		fprintf(logfile, "[ERROR] not possible to write dos stub\n");
		return false;
	}

	fprintf(stderr, "[INFO] Writing to file nt header\n");
	fprintf(logfile, "[INFO] Writing to file nt header\n");
	written_bytes = fwrite(&nt_coff_header->get_nt_header(), sizeof(nt_coff_header->get_nt_header()), 1, dumped_file);

	if (!written_bytes)
	{
		fprintf(stderr, "[ERROR] not possible to write nt header\n");
		fprintf(logfile, "[ERROR] not possible to write nt header\n");
		return false;
	}

	fprintf(stderr, "[INFO] Writing to file optional header\n");
	fprintf(logfile, "[INFO] Writing to file optional header\n");

	if (optional_header->is_64_bit_binary())
	{
		written_bytes = fwrite(&optional_header->get_optional_image().optional_64,
			sizeof(optional_header->get_optional_image().optional_64),
			1,
			dumped_file);

		if (!written_bytes)
		{
			fprintf(stderr, "[ERROR] not possible to write optional header\n");
			fprintf(logfile, "[ERROR] not possible to write optional header\n");
			return false;
		}

		fprintf(stderr, "[INFO] Writing to file data directories\n");
		fprintf(logfile, "[INFO] Writing to file data directories\n");

		for (i = 0; i < optional_header->get_optional_image().optional_64.numberOfRvaAndSizes; i++)
		{
			written_bytes = fwrite(&data_directory_header->get_data_directories().at(i),
				sizeof(data_directory_header->get_data_directories().at(i)),
				1,
				dumped_file);

			if (!written_bytes)
			{
				fprintf(stderr, "[ERROR] not possible to write data directories\n");
				fprintf(logfile, "[ERROR] not possible to write data directories\n");
				return false;
			}
		}
	}
	else
	{
		written_bytes = fwrite(&optional_header->get_optional_image().optional_32,
			sizeof(optional_header->get_optional_image().optional_32),
			1,
			dumped_file);

		if (!written_bytes)
		{
			fprintf(stderr, "[ERROR] not possible to write optional header\n");
			fprintf(logfile, "[ERROR] not possible to write optional header\n");
			return false;
		}

		fprintf(stderr, "[INFO] Writing to file data directories\n");
		fprintf(logfile, "[INFO] Writing to file data directories\n");

		for (i = 0; i < optional_header->get_optional_image().optional_32.numberOfRvaAndSizes; i++)
		{
			written_bytes = fwrite(&data_directory_header->get_data_directories().at(i),
				sizeof(data_directory_header->get_data_directories().at(i)),
				1,
				dumped_file);

			if (!written_bytes)
			{
				fprintf(stderr, "[ERROR] not possible to write data directories\n");
				fprintf(logfile, "[ERROR] not possible to write data directories\n");
				return false;
			}
		}
	}

	fprintf(stderr, "[INFO] Writing to file section header\n");
	fprintf(logfile, "[INFO] Writing to file section header\n");
	for (i = 0; i < nt_coff_header->get_nt_header().numberOfSections; i++)
	{
		written_bytes = fwrite(&section_table_header->get_sections().at(i),
			sizeof(section_table_header->get_sections().at(i)),
			1,
			dumped_file);

		if (!written_bytes)
		{
			fprintf(stderr, "[ERROR] not possible to write section header\n");
			fprintf(logfile, "[ERROR] not possible to write section header\n");
			return false;
		}
	}

	return true;
}

bool memory_dumper_t::write_sections_to_file()
{
	const size_t block_size = 1024;
	size_t bytes_to_write, read_bytes, write_bytes, i;
	uint8_t* section_buffer;
	ADDRINT address_to_read;

	section_buffer = (uint8_t*)malloc(block_size);
	for (i = 0; i < nt_coff_header->get_nt_header().numberOfSections; i++)
	{
		bytes_to_write = section_table_header->get_sections().at(i).sizeOfRawData;
		address_to_read = base_address_to_dump + section_table_header->get_sections().at(i).virtualAddress;

		fprintf(stderr, "[INFO] Section virtual address: 0x%x, size of raw data: 0x%x, pointer to raw data: 0x%x\n", address_to_read, bytes_to_write, section_table_header->get_sections().at(i).pointerToRawData);
		fprintf(logfile, "[INFO] Section virtual address: 0x%x, size of raw data: 0x%x, pointer to raw data: 0x%x\n", address_to_read, bytes_to_write, section_table_header->get_sections().at(i).pointerToRawData);

		if (fseek(dumped_file, section_table_header->get_sections().at(i).pointerToRawData, SEEK_SET))
			return false;
		
		while (bytes_to_write != 0)
		{
			if (bytes_to_write < 1024)
			{
				read_bytes = PIN_SafeCopy(section_buffer, (const VOID*)address_to_read, bytes_to_write);
				if (read_bytes != bytes_to_write)
				{
					free(section_buffer);
					return false;
				}
			}
			else
			{
				read_bytes = PIN_SafeCopy(section_buffer, (const VOID*)address_to_read, 1024);
				if (read_bytes != 1024)
				{
					free(section_buffer);
					return false;
				}
			}

			write_bytes = fwrite(section_buffer, read_bytes, 1, dumped_file);

			if (!write_bytes)
			{
				free(section_buffer);
				return false;
			}

			bytes_to_write -= read_bytes;
			address_to_read += read_bytes;
		}
	}
	free(section_buffer);
	return true;
}