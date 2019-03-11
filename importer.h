#pragma once

#ifndef IMPORTER_H
#define IMPORTER_H

#include "common.h"
#include "dos_header.h"
#include "nt_header.h"
#include "optional_header.h"
#include "data_directory_header.h"
#include "section_header.h"

class Importer
{
public:

	enum name_or_ordinal_enum_t
	{
		function_is_name	= 0,
		function_is_ordinal	= 1
	};

	struct import_directory_names_struct_t
	{
		std::string							dll_name;
		uint32_t							first_thunk;
		std::vector<name_or_ordinal_enum_t>	name_or_ordinal;
		std::vector<std::string>			function_names;
		std::vector<uint16_t>				function_ordinals;

		bool operator<(const import_directory_names_struct_t& a) const
		{
			return first_thunk < a.first_thunk;
		}
	};

#pragma pack(1)
	struct import_directory_struct_t {
		uint32_t originalFirstThunk;
		uint32_t timeDateStamp;
		uint32_t forwarderChain;
		uint32_t nameRVA;
		uint32_t firstThunk;
	};
#pragma pack()
	static const uint64_t ordinal_constant_64_binary = 0x8000000000000000;
	static const uint32_t ordinal_constant_32_binary = 0x80000000;

	Importer(pe_parser::dos_header_t *dos_header,
		pe_parser::nt_header_t *nt_coff_header,
		pe_parser::optional_header_t *optional_header,
		pe_parser::data_directory_header_t *data_directory_header,
		pe_parser::section_header_t *section_table_header);

	~Importer() = default;

	void ImporterAddNewDll(const char* dll_name);
	void ImporterAddNewDll(const wchar_t* dll_name);
	void ImporterAddNewAPI(const char* function_name);
	void ImporterAddNewAPIOrdinal(uint16_t function_ordinal);
	void ImporterSetNewFirstThunk(uint32_t first_thunk);

	std::vector<uint8_t> ImporterDumpToFile(uint32_t& rva_of_import_directory);
	std::vector<uintptr_t>  get_original_first_thunk();
	uint32_t get_rva_first_thunk();

private:
	void copy_name_to_buffer(std::vector<uint8_t>& buffer, std::string name);
	bool compare_by_first_thunk(const import_directory_names_struct_t& a, const import_directory_names_struct_t& b);

	/****** HEADER DATA ******/
	pe_parser::dos_header_t*						dos_header;
	pe_parser::nt_header_t*							nt_coff_header;
	pe_parser::optional_header_t*					optional_header;
	pe_parser::data_directory_header_t*				data_directory_header;
	pe_parser::section_header_t*					section_table_header;
	/****** Importer DATA ******/
	std::vector<import_directory_names_struct_t>	dlls_and_functions;
	import_directory_names_struct_t*				import_aux;
	std::vector<uint8_t>							raw_strings_dlls_and_functions;
	std::vector<uintptr_t>							new_original_first_thunk;
	std::vector<import_directory_struct_t>			imports_directories;
};

#endif // !IMPORTER_H
