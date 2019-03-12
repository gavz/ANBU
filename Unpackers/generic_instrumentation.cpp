
#include "generic_instrumentation.h"


/************* EXTERN VARIABLES *************/
extern FILE*						logfile; // log file handler


/************* VARIABLES USED FOR MONITORING BINARY *************/
ADDRINT								main_base_address;
dll_import_struct_t*				aux = nullptr;
std::vector<dll_import_struct_t*>	dll_imports;
bool								check_first_thunk = false;


void get_addresses_from_images(IMG img, VOID *v)
{
	RTN loadlibraryA;
	RTN loadlibraryW;
	RTN getprocaddress;

	fprintf(stderr, "[INFO] IMG Loaded: %s\n", IMG_Name(img).c_str());
	fprintf(logfile, "[INFO] IMG Loaded: %s\n", IMG_Name(img).c_str());

	if (IMG_IsMainExecutable(img)) 
	/*
	*	Check if the loaded executable is the main one
	*	in that case record the base address.
	*/
	{
		main_base_address = IMG_StartAddress(img);
		fprintf(stderr, "[INFO] Binary Base Address: 0x%x\n", main_base_address);
		fprintf(logfile, "[INFO] Binary Base Address: 0x%x\n", main_base_address);
		return;
	}

	loadlibraryA = RTN_FindByName(img, "LoadLibraryA");

	if (RTN_Valid(loadlibraryA))
	{
		RTN_Open(loadlibraryA);

		fprintf(stderr, "[INFO] Inserting callbacks for: %s\n", RTN_Name(loadlibraryA).c_str());

		RTN_InsertCall(loadlibraryA,
			IPOINT_BEFORE,
			(AFUNPTR)hook_loadlibrarya_before,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END
		);

		RTN_InsertCall(loadlibraryA,
			IPOINT_AFTER,
			(AFUNPTR)hook_loadlibrary_after,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);

		RTN_Close(loadlibraryA);
	}

	loadlibraryW = RTN_FindByName(img, "LoadLibraryW");

	if (RTN_Valid(loadlibraryW))
	{
		RTN_Open(loadlibraryW);

		fprintf(stderr, "[INFO] Inserting callbacks for: %s\n", RTN_Name(loadlibraryW).c_str());

		RTN_InsertCall(loadlibraryW,
			IPOINT_BEFORE,
			(AFUNPTR)hook_loadlibraryw_before,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END
		);

		RTN_InsertCall(loadlibraryW,
			IPOINT_AFTER,
			(AFUNPTR)hook_loadlibrary_after,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);

		RTN_Close(loadlibraryW);
	}

	getprocaddress = RTN_FindByName(img, "GetProcAddress");

	if (RTN_Valid(getprocaddress))
	{
		RTN_Open(getprocaddress);

		fprintf(stderr, "[INFO] Inserting callbacks for: %s\n", RTN_Name(getprocaddress).c_str());

		RTN_InsertCall(getprocaddress,
			IPOINT_BEFORE,
			(AFUNPTR)hook_getprocaddress_before,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END
		);

		RTN_InsertCall(getprocaddress,
			IPOINT_AFTER,
			(AFUNPTR)hook_getprocaddress_after,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);

		RTN_Close(getprocaddress);
	}

	return;
}

void hook_loadlibrarya_before(const char* dll_name)
{
	check_first_thunk = false;			// close the check of the first thunk copy

	if (aux == nullptr					// if aux is equals to nullptr
		|| strcmp(aux->dll_nameA.c_str(), dll_name) != 0)
	{
		aux = new dll_import_struct_t();
		aux->dll_nameA = dll_name;
		dll_imports.push_back(aux);

		fprintf(stderr, "[INFO] LoadLibraryA dll name: %s\n", dll_name);
		fprintf(logfile, "[INFO] LoadLibraryA dll name: %s\n", dll_name);
	}
}

void hook_loadlibraryw_before(const wchar_t* dll_name)
{
	check_first_thunk = false; // close the check of the first thunk copy

	if (aux == nullptr // if aux is equals to nullptr
		|| wcscmp(aux->dll_nameW.c_str(), dll_name) != 0)
	{
		aux = new dll_import_struct_t();
		aux->dll_nameW = dll_name;

		dll_imports.push_back(aux);

		fwprintf(stderr, L"[INFO] LoadLibraryW dll name: %S\n", dll_name);
		fwprintf(logfile, L"[INFO] LoadLibraryW dll name: %S\n", dll_name);
	}
}

void hook_loadlibrary_after(ADDRINT dll_address)
{
	aux->dll_address = dll_address;

	fprintf(stderr, "[INFO] LoadLibrary returned: 0x%x\n", dll_address);
	fprintf(logfile, "[INFO] LoadLibrary returned: 0x%x\n", dll_address);
}

void hook_getprocaddress_before(ADDRINT dll_address, const char* dll_name)
{
	check_first_thunk = false;

	// Create a new function
	if (aux)
	{
		function_struct_t func;

		if ((uintptr_t)dll_name <= 0xFFFF) // it is ordinal
		{
			func.function_ordinal = (uint16_t)((uintptr_t)dll_name & 0xFFFF);
			func.is_ordinal = true;
		}
		else
		{
			func.function_name = dll_name;
			func.is_ordinal = false;
		}

		aux->functions.push_back(func);
		PIN_LockClient();
		if (func.is_ordinal)
		{
			fprintf(stderr, "[INFO] dll 0x%x(%s), function 0x%x\n", dll_address, IMG_Name(IMG_FindByAddress(dll_address)).c_str(), func.function_ordinal);
			fprintf(logfile, "[INFO] dll 0x%x(%s), function 0x%x\n", dll_address, IMG_Name(IMG_FindByAddress(dll_address)).c_str(), func.function_ordinal);
		}
		else
		{
			fprintf(stderr, "[INFO] dll 0x%x(%s), function %s\n", dll_address, IMG_Name(IMG_FindByAddress(dll_address)).c_str(), dll_name);
			fprintf(logfile, "[INFO] dll 0x%x(%s), function %s\n", dll_address, IMG_Name(IMG_FindByAddress(dll_address)).c_str(), dll_name);	
		}
		PIN_UnlockClient();

	}
}

void hook_getprocaddress_after(ADDRINT function_address)
{
	check_first_thunk = true;

	fprintf(stderr, "[INFO] GetProcAddress returned: 0x%x\n", function_address);
	fprintf(logfile, "[INFO] GetProcAddress returned: 0x%x\n", function_address);

	// add the function address to the last function
	if (aux)
	{
		aux->functions.at(
			aux->functions.size() - 1
		).function_address = function_address;
	}
}