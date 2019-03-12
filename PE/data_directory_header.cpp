
#include "data_directory_header.h"

/************* EXTERN VARIABLES *************/
extern FILE *logfile; // log file handler

namespace pe_parser
{
	data_directory_header_t::data_directory_header_t(ADDRINT address, uint32_t number_of_rva_and_sizes, uint32_t size_of_image)
	{
		size_t copied_size, size_to_copy = sizeof(data_directory_struct_t);
		size_t i;
		data_directory_struct_t data_directory_aux;
		data_directory_correct = true;
		this->number_of_rva_and_sizes = number_of_rva_and_sizes;

		for (i = 0; i < number_of_rva_and_sizes; i++)
		{
			copied_size = PIN_SafeCopy((VOID*)&data_directory_aux, (const VOID*)(address + (i * size_to_copy)), size_to_copy);

			if (copied_size != size_to_copy)
			{
				data_directory_correct = false;
				return;
			}

			if (data_directory_aux.virtualAddress > size_of_image ||
				(data_directory_aux.virtualAddress + data_directory_aux.size) > size_of_image)
			{
				data_directory_correct = false;
				return;
			}
		
			data_directories.push_back(data_directory_aux);
		}
		/* I couldn't initialize the map with as many values, so I do it in the constructor */
		directory_names[export_table_k]				= "Export Table";
		directory_names[import_table_k]				= "Import Table";
		directory_names[resource_table_k]			= "Resource Table";
		directory_names[exception_table_k]			= "Exception Table";
		directory_names[certificate_table_k]		= "Certificate Table";
		directory_names[base_relocation_table_k]	= "Base Relocation Table";
		directory_names[debug_k]					= "Debug";
		directory_names[architecture_k]				= "Architecture";
		directory_names[global_ptr_k]				= "Global Ptr";
		directory_names[tls_table_k]				= "TLS Table";
		directory_names[load_config_table_k]		= "Load Config Table";
		directory_names[bound_import_k]				= "Bound Import";
		directory_names[iat_k]						= "IAT";
		directory_names[delay_import_descriptor_k]	= "Delay Import Descriptor";
		directory_names[clr_runtime_header_k]		= "CLR Runtime Header";
		directory_names[reserved_k]					= "Reserved";
	}

	std::vector<data_directory_header_t::data_directory_struct_t>& data_directory_header_t::get_data_directories()
	{
		return data_directories;
	}

	bool data_directory_header_t::is_data_directory_correct()
	{
		return data_directory_correct;
	}

	bool data_directory_header_t::dump_directories()
	{
		size_t i = 0;

		if (!data_directory_correct)
			return false;

		fprintf(logfile, "================== DUMP DATA DIRECTORIES ===================\n");
		
		for (i = 0; i < number_of_rva_and_sizes; i++)
		{
			fprintf(logfile, "\t+Name: %s\n", directory_names[i].c_str());
			fprintf(logfile, "\t+Virtual Address: 0x%x\n", data_directories[i].virtualAddress);
			fprintf(logfile, "\t+Size: 0x%x\n", data_directories[i].size);
		}

		return true;
	}
}