#pragma once

#ifndef GENERIC_INSTRUMENTATION_H
#define GENERIC_INSTRUMENTATION_H

#include "common.h"
#include "importer.h"
#include "pe_file.h"

/****** Structures used for monitoring functions ******/
typedef struct function_struct_t_
{
	bool		is_ordinal;
	uint16_t	function_ordinal;
	std::string function_name;
	ADDRINT		function_address;
	ADDRINT		function_destination;
} function_struct_t;

typedef struct dll_import_struct_t_
{
	std::string						dll_nameA;
	std::wstring					dll_nameW;
	ADDRINT							dll_address;
	std::vector<function_struct_t>	functions;
}  dll_import_struct_t;


/***** INSTRUMENTATION FUNCTIONS *****/
void get_addresses_from_images(IMG img, VOID *v);

void hook_loadlibrarya_before(const char* dll_name);
void hook_loadlibrary_after(ADDRINT dll_address);

void hook_loadlibraryw_before(const wchar_t* dll_name);

void hook_getmodulehandlea_before(const char* dll_name);
void hook_getmodulehandlew_before(const wchar_t* dll_name);

void hook_getprocaddress_before(ADDRINT dll_address, const char* function_name);
void hook_getprocaddress_after(ADDRINT function_address);

#endif // !GENERIC_INSTRUMENTATION_H
