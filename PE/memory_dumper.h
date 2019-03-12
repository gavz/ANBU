#pragma once

#ifndef MEMORY_DUMPER_H
#define MEMORY_DUMPER_H

#include "common.h"
#include "dos_header.h"
#include "nt_header.h"
#include "optional_header.h"
#include "data_directory_header.h"
#include "section_header.h"
#include "importer.h"
#include "generic_instrumentation.h"

class memory_dumper_t
/***
*	Class to parse and dump a PE file from memory to
*	disk. Some of things I had to include comparing
*	with other dumpers is the use of the function
*	PE_SafeCopy to get the data.
*/
{
public:
	memory_dumper_t(ADDRINT jump_target);
	memory_dumper_t(std::vector<uint8_t> file_base_in_vector);
	~memory_dumper_t();
	
	bool parse_memory();

	bool dump_pe_to_file();
	bool dump_runpe_to_file(std::vector<write_memory_t> file_data, ADDRINT base_address);

	uint64_t rva_to_offset(uint64_t rva);
	uint64_t offset_to_rva(uint64_t offset);

	pe_parser::data_directory_header_t*	get_data_directories();
	pe_parser::section_header_t* get_section_table_header();
	Importer* get_importer();
private:
	/**** Private Functions ****/
	bool parse_and_check_dos_header(ADDRINT address);
	bool read_dos_stub(ADDRINT address);
	bool parse_and_check_nt_header(ADDRINT address);
	bool parse_and_check_optional_header(ADDRINT address);
	bool parse_and_check_data_directories(ADDRINT address);
	bool parse_and_check_section_headers(ADDRINT address);
	bool check_import_directory();
	bool check_export_directory();
	bool check_relocation_directory();
	uint32_t calc_correct_size_of_headers();
	bool create_new_section(std::vector<uint8_t> buffer, uint32_t characteristics, const char *name);
	/**** Private dump functions ****/
	uint64_t realign_pe();
	bool write_headers_to_file();
	bool write_sections_to_file();

	pe_parser::dos_header_t *dos_header;
	pe_parser::nt_header_t *nt_coff_header;
	pe_parser::optional_header_t *optional_header;
	pe_parser::data_directory_header_t *data_directory_header;
	pe_parser::section_header_t *section_table_header;


	Importer*	importer;
	FILE*		dumped_file;
	ADDRINT		address_code_to_dump;
	ADDRINT		base_address_to_dump;
	ADDRINT		base_address_name;
	IMG			img_to_dump;
	bool		headers_correct;
	uint8_t*	dos_stub;
	bool		dump_correct;
	char		file_name[200];
	std::vector<uint8_t> data_from_vector;
};

#endif // !MEMORY_DUMPER_H
