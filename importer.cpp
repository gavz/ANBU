#include "importer.h"

Importer::Importer(pe_parser::dos_header_t *dos_header,
	pe_parser::nt_header_t *nt_coff_header,
	pe_parser::optional_header_t *optional_header,
	pe_parser::data_directory_header_t *data_directory_header,
	pe_parser::section_header_t *section_table_header) : import_aux(nullptr)
{
	this->dos_header				= dos_header;
	this->nt_coff_header			= nt_coff_header;
	this->optional_header			= optional_header;
	this->data_directory_header		= data_directory_header;
	this->section_table_header		= section_table_header;
}

void Importer::ImporterAddNewDll(const char* dll_name)
{
	// check if import aux contains some data
	// in that case add it to dlls_and_functions
	// vector, and set import_aux pointer to null
	if (import_aux != nullptr) 
	{
		dlls_and_functions.push_back(*import_aux);
		import_aux = nullptr;
	}
	// for each dll, we will create an import
	// structure.
	import_aux = new import_directory_names_struct_t();
	import_aux->dll_name = dll_name;
}

void Importer::ImporterAddNewDll(const wchar_t* dll_name)
{
	// check if import aux contains some data
	// in that case add it to dlls_and_functions
	// vector, and set import_aux pointer to null
	if (import_aux != nullptr)
	{
		dlls_and_functions.push_back(*import_aux);
		import_aux = nullptr;
	}
	// Sorry wide char, we will use ascii...
	char* dll_nameA = (char*)calloc(1, wcslen(dll_name) + 1);
	wcstombs(dll_nameA, dll_name, wcslen(dll_name) + 1);
	// for each dll, we will create an import
	// structure.
	import_aux = new import_directory_names_struct_t();
	import_aux->dll_name = dll_nameA;
	// we don't need this memory anymore
	free(dll_nameA);
}

void Importer::ImporterAddNewAPI(const char* function_name)
{
	// Add new API by name, all the functions are imported
	// in ascii
	std::string aux(function_name);
	import_aux->function_names.push_back(aux);
	import_aux->name_or_ordinal.push_back(function_is_name);
}

void Importer::ImporterAddNewAPIOrdinal(uint16_t function_ordinal)
{
	// Add new API by ordinal, 16 bits ordinal.
	import_aux->function_ordinals.push_back(function_ordinal);
	import_aux->name_or_ordinal.push_back(function_is_ordinal);
}

void Importer::ImporterSetNewFirstThunk(uint32_t first_thunk)
{
	// RVA to the first thunk, it is necessary to point to the same
	// IAT as the original file to dump the file correctly.
	this->import_aux->first_thunk = first_thunk;
}

std::vector<uint8_t> Importer::ImporterDumpToFile(uint32_t& rva_of_import_directory)
{
	if (import_aux != nullptr)
	{
		// we still have one import to push
		dlls_and_functions.push_back(*import_aux);
		import_aux = nullptr;
	}

	std::vector<uint8_t> buffer;

	// if no dlls, return empty buffer
	if (dlls_and_functions.empty())
		return buffer;

	// order by first thunk
	// so when we have to dump it
	// we will have everything
	// sorted
	std::sort(dlls_and_functions.begin(), dlls_and_functions.end());

	uint32_t new_section_virtual_address = 0;
	uint32_t last_section_virtual_size_aligned = 0;
	uint32_t section_alignment;
	uint64_t size_for_original_first_thunk_and_import_directories = 0; // total size of original first thunk and import directories
	if (optional_header->is_64_bit_binary())
		section_alignment = optional_header->get_optional_image().optional_64.sectionAlignment;
	else
		section_alignment = optional_header->get_optional_image().optional_32.sectionAlignment;

	auto sections = section_table_header->get_sections();
	auto last_section = sections.at(sections.size() - 1);

	// get new base address
	last_section_virtual_size_aligned = last_section.virtualSize;
	if ((last_section_virtual_size_aligned % section_alignment) > 0)
		last_section_virtual_size_aligned = last_section_virtual_size_aligned + (section_alignment - (last_section_virtual_size_aligned % section_alignment));

	new_section_virtual_address = last_section.virtualAddress + last_section_virtual_size_aligned;

	// set vector for strings
	for (size_t dll_names = 0; dll_names < dlls_and_functions.size(); dll_names++)
	{
		// add the string of dll name
		copy_name_to_buffer(raw_strings_dlls_and_functions, dlls_and_functions.at(dll_names).dll_name);

		/*
		*	Calculate the size for the original first thunk as:
		*
		*		(number of functions * size_of_pointers) + size of NULL pointer
		*/
		size_for_original_first_thunk_and_import_directories += (dlls_and_functions.at(dll_names).name_or_ordinal.size() * sizeof(uintptr_t)) + sizeof(uintptr_t);
	
		for (size_t function_names = 0; function_names < dlls_and_functions.at(dll_names).function_names.size(); function_names++)
		{
			// add string hints
			raw_strings_dlls_and_functions.push_back(0);
			raw_strings_dlls_and_functions.push_back(0);
			// add the string of the function name
			copy_name_to_buffer(raw_strings_dlls_and_functions, dlls_and_functions.at(dll_names).function_names.at(function_names));
		}
	}

	/*
	*	Calculate new size of import directories as:
	*
	*		(number of import directories * size of import directories) + size of NULL import directory.
	*
	*	This size will be the offset of the section that we will use for the strings, also
	*	this will be used to set the RVAs on the original first thunks.
	*/
	size_for_original_first_thunk_and_import_directories += dlls_and_functions.size() * sizeof(import_directory_struct_t);
	size_for_original_first_thunk_and_import_directories += sizeof(import_directory_struct_t);

	/*
	*	Now set the vector for the original first thunks.
	*	As we have the offset of the strings will be useful
	*/
	for (size_t dll_names = 0; dll_names < dlls_and_functions.size(); dll_names++)
	{
		size_t index_names		= 0;
		size_t index_ordinals	= 0;

		for (size_t functions = 0; functions < dlls_and_functions.at(dll_names).name_or_ordinal.size(); functions++)
		{

			if (dlls_and_functions.at(dll_names).name_or_ordinal.at(functions) == function_is_ordinal)
			{
				if (optional_header->is_64_bit_binary())
					new_original_first_thunk.push_back((uintptr_t)ordinal_constant_64_binary | dlls_and_functions.at(dll_names).function_ordinals.at(index_ordinals));
				else
					new_original_first_thunk.push_back((uintptr_t)ordinal_constant_32_binary | dlls_and_functions.at(dll_names).function_ordinals.at(index_ordinals));
				index_ordinals++;
			}

			else
			{
				std::string name = dlls_and_functions.at(dll_names).function_names.at(index_names);
				/*
				*	Calculate the offset of the name, for that task
				*	calculate the offset where the name appears on the 
				*	raw_strings_of_dll_and_functions, with that we will
				*	have the offset to the string, we will have to add
				*	the virtual address of the section, and finally the
				*	size of the import directories, we substrate 2 to point
				*	to the hint of the name
				*/
				uintptr_t offset_of_name = (uintptr_t)(
					std::search(
					(const char*)raw_strings_dlls_and_functions.begin(),
						(const char*)(raw_strings_dlls_and_functions.begin() + raw_strings_dlls_and_functions.size()),
						name.c_str(),
						name.c_str() + name.size() + 1
					));
				offset_of_name = offset_of_name - (uintptr_t)raw_strings_dlls_and_functions.begin();
				
				new_original_first_thunk.push_back(new_section_virtual_address + // take base
					(uintptr_t)size_for_original_first_thunk_and_import_directories + // plus size of original first thunk and import directories
					offset_of_name - // plus offset of the name inside of the vector
					2 // - 2 to point to the hint
				);

				index_names++;
			}

		}
		new_original_first_thunk.push_back(0); // 0 to finish the original first thunk
	}

	/*
	*	Now set a vector for the import directories
	*/
	import_directory_struct_t import_directory_aux = { 0 };
	uint32_t original_first_thunk = new_section_virtual_address; // the first original first thunk, will be the base of the new section in memory
	for (size_t dll_names = 0; dll_names < dlls_and_functions.size(); dll_names++)
	{
		// search now offset of the dll name in the buffer with the strings
		uint32_t offset_of_dll_name = (uint32_t)(std::search(
			(const char*)raw_strings_dlls_and_functions.begin(),
			(const char*)raw_strings_dlls_and_functions.begin() + raw_strings_dlls_and_functions.size(),
			dlls_and_functions.at(dll_names).dll_name.c_str(),
			dlls_and_functions.at(dll_names).dll_name.c_str() + dlls_and_functions.at(dll_names).dll_name.size()
		));
		offset_of_dll_name -= (uint32_t)raw_strings_dlls_and_functions.begin();
		
		// finally create new import directory
		import_directory_aux.nameRVA = (
			new_section_virtual_address + // base
			(uint32_t)size_for_original_first_thunk_and_import_directories + // plus size of original first thunk
			offset_of_dll_name // plus offset of dll name
			);

		import_directory_aux.firstThunk = dlls_and_functions.at(dll_names).first_thunk;
		import_directory_aux.originalFirstThunk = original_first_thunk;
		imports_directories.push_back(import_directory_aux);
		// now advance the original first thunk
		original_first_thunk += (dlls_and_functions.at(dll_names).name_or_ordinal.size() * sizeof(uintptr_t)) + sizeof(uintptr_t);
	}
	// add the last one with 0s
	import_directory_aux = { 0 };
	imports_directories.push_back(import_directory_aux);

	// finally the last vector will be the union of the others
	size_t size = raw_strings_dlls_and_functions.size() +
		new_original_first_thunk.size() * sizeof(uintptr_t) +
		imports_directories.size() * sizeof(import_directory_struct_t);
	
	buffer.resize(size);
	uint8_t *p_buffer = buffer.begin();

	// first add the new original first thunk
	for (size_t i = 0; i < new_original_first_thunk.size(); i++)
	{
		((uintptr_t*)p_buffer)[i] = new_original_first_thunk[i];
	}
	
	p_buffer += (new_original_first_thunk.size() * sizeof(uintptr_t));

	// add the import directories
	for (size_t i = 0; i < imports_directories.size(); i++)
	{
		((import_directory_struct_t*)p_buffer)[i].firstThunk			= imports_directories.at(i).firstThunk;
		((import_directory_struct_t*)p_buffer)[i].forwarderChain		= imports_directories.at(i).forwarderChain;
		((import_directory_struct_t*)p_buffer)[i].originalFirstThunk	= imports_directories.at(i).originalFirstThunk;
		((import_directory_struct_t*)p_buffer)[i].timeDateStamp			= imports_directories.at(i).timeDateStamp;
		((import_directory_struct_t*)p_buffer)[i].nameRVA				= imports_directories.at(i).nameRVA;
	}

	p_buffer += (imports_directories.size() * sizeof(import_directory_struct_t));

	// finally add the raw strings
	for (size_t i = 0; i < raw_strings_dlls_and_functions.size(); i++)
	{
		p_buffer[i] = raw_strings_dlls_and_functions[i];
	}

	// calculate the rva of new import directories to set it at header
	rva_of_import_directory = (uint32_t)(new_section_virtual_address + (new_original_first_thunk.size() * sizeof(uintptr_t)));
	return buffer;
}

std::vector<uintptr_t>  Importer::get_original_first_thunk()
{
	return new_original_first_thunk;
}

uint32_t Importer::get_rva_first_thunk()
{
	if (imports_directories.size() > 0)
		return imports_directories.at(0).firstThunk;

	return 0;
}

void Importer::copy_name_to_buffer(std::vector<uint8_t>& buffer, std::string name)
{
	// simple function to extract bytes from string and copy
	// it to a vector
	for (size_t i = 0; i < name.size(); i++)
	{
		buffer.push_back(name.at(i));
	}
	buffer.push_back(0);
}

bool Importer::compare_by_first_thunk(const import_directory_names_struct_t& a, const import_directory_names_struct_t& b)
{
	return a.first_thunk < b.first_thunk;
}