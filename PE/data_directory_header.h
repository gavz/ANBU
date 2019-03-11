#pragma once

#ifndef DATA_DIRECTORY_HEADER_H
#define DATA_DIRECTORY_HEADER_H

#include "common.h"

namespace pe_parser
{
	class data_directory_header_t
	{
	public:
#pragma pack(1)
		struct data_directory_struct_t 
		{
			uint32_t virtualAddress;
			uint32_t size;
		};
#pragma pack()

		enum
		{
			export_table_k = 0,
			import_table_k,
			resource_table_k,
			exception_table_k,
			certificate_table_k,
			base_relocation_table_k,
			debug_k,
			architecture_k,
			global_ptr_k,
			tls_table_k,
			load_config_table_k,
			bound_import_k,
			iat_k,
			delay_import_descriptor_k,
			clr_runtime_header_k,
			reserved_k
		};

		std::map<uint32_t, string> directory_names;

		data_directory_header_t(ADDRINT address, uint32_t number_of_rva_and_sizes, uint32_t size_of_image);
		~data_directory_header_t() = default;

		std::vector<data_directory_struct_t>& get_data_directories();
		bool is_data_directory_correct();
		bool dump_directories();

	private:
		bool data_directory_correct;
		std::vector<data_directory_struct_t> data_directories;
		uint32_t number_of_rva_and_sizes;
	};
}

#endif // !DATA_DIRECTORY_HEADER_H
