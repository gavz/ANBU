#pragma once

#ifndef PE_FILE_H
#define PE_FILE_H

#include "common.h"
#include "dos_header.h"
#include "nt_header.h"
#include "optional_header.h"
#include "data_directory_header.h"
#include "section_header.h"

class pe_file
{
public:
	pe_file(ADDRINT binary_address);
	pe_file(IMG binary_img);
	~pe_file();

	bool		analyze_binary();
	bool		has_section_changed_entropy(ADDRINT address_of_section);
	bool		on_pe_file(ADDRINT address);

private:
	float		calculate_entropy_section(pe_parser::section_header_t::section_struct_t section);
	bool		calculate_initial_entropy();
	bool		parse_pe_header();
	bool		entropy_higher_than_HE(uint32_t entropy);
	bool		entropy_lower_than_LE(uint32_t entropy);
	/**** Parsing functions ****/
	bool		parse_and_check_dos_header(ADDRINT address);
	bool		read_dos_stub(ADDRINT address);
	bool		parse_and_check_nt_header(ADDRINT address);
	bool		parse_and_check_optional_header(ADDRINT address);
	bool		parse_and_check_data_directories(ADDRINT address);
	bool		parse_and_check_section_headers(ADDRINT address);

	const float							entropy_threshold = 10.0;


	ADDRINT								binary_base_address;
	size_t								number_of_sections;
	IMG									binary_img;
	bool								binary_is_okay;
	bool								headers_are_correct;

	
	float*								initial_entropies			= nullptr;

	pe_parser::dos_header_t*			dos_header					= nullptr;
	uint8_t*							dos_stub					= nullptr;
	pe_parser::nt_header_t*				nt_coff_header				= nullptr;
	pe_parser::optional_header_t*		optional_header				= nullptr;
	pe_parser::data_directory_header_t*	data_directory_header		= nullptr;
	pe_parser::section_header_t*		section_table_header		= nullptr;
};


#endif // !PE_FILE_H
