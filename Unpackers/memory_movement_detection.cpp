
#include "memory_movement_detection.h"

/******************* Data for the unpacker *******************/
extern FILE*						logfile;			// log file handler
std::map<ADDRINT, mem_access_t>		shadow_mem;			// map memory addresses with memory
														// access permissions.
std::vector<mem_cluster_t>			clusters;			// vector to store all the unpacked memory
														// clusters found
ADDRINT								saved_addr;			// temporary variable needed for storing state between
														// two analysis routines
extern ADDRINT						main_base_address;	// main base address of binary, to start
														// reading PE file

/******************* Variables for dump *******************/
memory_dumper_t*					memory_dumper;		// dumper for the PE file

extern KNOB<string> KnobLogFile;

extern std::vector<dll_import_struct_t*> dll_imports;

extern bool check_first_thunk;


/******************* Functions for the unpacker *******************/

void fini(INT32 code, void *v)
/*
*   Function that will be executed at the end
*   of the execution or when PIN detachs from
*   the process.
*/
{
	fprintf(stderr, "------ unpacking complete ------\n");
	fprintf(logfile, "------ unpacking complete ------\n");

	// save final log and close file
	fprintf(stderr, "------ end log ------\n");
	fprintf(logfile, "------ end log ------\n");
	fclose(logfile);
}

void instrument_mem_cflow(INS ins, void *v)
/*
*   Function to instrument each instruction
*   we will use this function to record the
*   written memory, and the jumps to those
*   memory.
*/
{
	if (INS_IsMemoryWrite(ins)      
		&& INS_hasKnownMemorySize(ins))
	{
		// this first three callbacks will be used for tracking memory writes

		INS_InsertPredicatedCall(
			ins,
			IPOINT_BEFORE,              
			(AFUNPTR)queue_memwrite,	
			IARG_MEMORYWRITE_EA,        
			IARG_END                    
		);


		// For REP instructions

		// if no more REPs, execute next instruction
		if (INS_HasFallThrough(ins))
		{
			INS_InsertPredicatedCall(
				ins,
				IPOINT_AFTER,           
				(AFUNPTR)log_memwrite,  
				IARG_MEMORYWRITE_SIZE,  
				IARG_END                
			);
		}

		// check if it is REP or another kind of branch or call instruction to copy
		if (INS_IsBranchOrCall(ins))
		{
			INS_InsertPredicatedCall(
				ins,
				IPOINT_TAKEN_BRANCH,        
				(AFUNPTR)log_memwrite,      
				IARG_MEMORYWRITE_SIZE,      
				IARG_END                    
			);
		}
	}

	// check if jumped to unpacked code
	if ((INS_IsDirectBranch(ins) || INS_IsIndirectBranchOrCall(ins))
		&& INS_OperandCount(ins) > 0)
	{
		INS_InsertCall(
			ins,
			IPOINT_BEFORE,                      
			(AFUNPTR)check_indirect_ctransfer,  
			IARG_INST_PTR,                      
			IARG_BRANCH_TARGET_ADDR,            
			IARG_END                            
		);
	}
}

void queue_memwrite(ADDRINT addr)
/*
*   Function which will save for a moment the address
*   of the instruction which will copy memory.
*   This is necessary as only before of the instruction
*   execution is possible to record the address
*/
{
	saved_addr = addr;
}

void log_memwrite(UINT32 size)
/*
*   Function to log in shared_mem the address and the size of
*   copied data from a copy instruction
*/
{
	ADDRINT addr = saved_addr;

	for (ADDRINT i = addr; i < addr + size; i++)
	{
		shadow_mem[i].w = true;
		PIN_SafeCopy(&(shadow_mem[i].val), (const void*)i, 1);
	}


	// check if is writing an API to memory
	// only will be executed after a GetProcAddress
	if (check_first_thunk && size == sizeof(ADDRINT))
	{
		ADDRINT api_write;
		PIN_SafeCopy((VOID*)&api_write, (const VOID*)addr, sizeof(ADDRINT));

		for (size_t i = 0; i < dll_imports.size(); i++)
		{
			for (size_t j = 0; j < dll_imports.at(i)->functions.size(); j++)
			{
				if (dll_imports.at(i)->functions.at(j).function_address == api_write) // check which API is writing
				{
					PIN_LockClient();
					dll_imports.at(i)->functions.at(j).function_destination = addr - IMG_StartAddress(IMG_FindByAddress(addr));
					PIN_UnlockClient();

					fprintf(stderr, "[INFO] API %s (0x%x) written to: 0x%x\n",
						dll_imports.at(i)->functions.at(j).function_name.c_str(),
						dll_imports.at(i)->functions.at(j).function_address,
						dll_imports.at(i)->functions.at(j).function_destination);

					fprintf(logfile, "[INFO] API %s (0x%x) written to: 0x%x\n",
						dll_imports.at(i)->functions.at(j).function_name.c_str(),
						dll_imports.at(i)->functions.at(j).function_address,
						dll_imports.at(i)->functions.at(j).function_destination);

					check_first_thunk = false;

					return;
				}
			}
		}
	}
}

void check_indirect_ctransfer(ADDRINT ip, ADDRINT target)
/*
*   Function to detect the jump to the OEP and dump the unpacked code.
*   we will use the shadow_mem to detect if a memory was used as a target
*   of a copy, we will taint that memory as possible OEP.
*/
{
	mem_cluster_t c;

	shadow_mem[target].x = true;

	if (shadow_mem[target].w && !in_cluster(target))
	{
		fprintf(stderr, "[INFO] Jumped to the address: 0x%x, written before\n", target);
		fprintf(logfile, "[INFO] Jumped to the address: 0x%x, written before\n", target);

		set_cluster(target, &c);
		clusters.push_back(c);

 		mem_to_file(&c, target);

		PIN_LockClient();
		if (dump_to_file(&c, target))
		{
			PIN_UnlockClient();

			PIN_ExitProcess(0);
		}
		PIN_UnlockClient();
	}
}

void mem_to_file(mem_cluster_t *c, ADDRINT entry)
{
	FILE *f;
	char buf[256];

	fprintf(stderr, "[INFO] extracting unpacked region 0x%x %c%c entry 0x%x\n",
		(uintptr_t)c->base, c->w ? 'w' : '-', c->x ? 'x' : '-', (uintptr_t)entry);
	fprintf(logfile, "[INFO] extracting unpacked region 0x%x %c%c entry 0x%x\n",
		(uintptr_t)c->base, c->w ? 'w' : '-', c->x ? 'x' : '-', (uintptr_t)entry);

	snprintf(buf, sizeof(buf), "unpacked.0x%x-0x%x_entry-0x%x",
		(uintptr_t)c->base, (uintptr_t)(c->base + c->size), (uintptr_t)entry);

	f = fopen(buf, "wb");
	if (!f)
	{
		fprintf(stderr, "[ERROR] failed to open file '%s' for writing\n", buf);
		fprintf(logfile, "[ERROR] failed to open file '%s' for writing\n", buf);
	}
	else
	{
		for (ADDRINT i = c->base; i < c->base + c->size; i++)
		{
			if (fwrite((const void*)&shadow_mem[i].val, 1, 1, f) != 1)
			{
				fprintf(stderr, "[ERROR] failed to write unpacked byte 0x%x to file '%s'\n", (unsigned int)i, buf);
				fprintf(logfile, "[ERROR] failed to write unpacked byte 0x%x to file '%s'\n", (unsigned int)i, buf);
			}
		}

		fclose(f);
	}
}

void set_cluster(ADDRINT target, mem_cluster_t *c)
/*
*   Calculate memory cluster using target and shadow_mem
*   it will calculate base address and size.
*/
{
	ADDRINT addr, base;
	unsigned long size;
	bool w, x;
	std::map<ADDRINT, mem_access_t>::iterator i, j;

	j = shadow_mem.find(target);
	assert(j != shadow_mem.end());

	base = target;
	w = false;
	x = false;

	for (i = j; ; i--)
	{
		addr = i->first;

		if (addr == base)
		{
			if (i->second.w)
				w = true;
			if (i->second.x)
				x = true;
			base--;
		}
		else
		{
			base++; 
			break;
		}

		if (i == shadow_mem.begin())
		{
			base++;
			break;
		}
	}

	size = target - base;
	for (i = j; i != shadow_mem.end(); i++)
	{
		addr = i->first;
		if (addr == base + size)
		{
			if (i->second.w)
				w = true;
			if (i->second.x)
				x = true;
			size++;
		}
		else
		{
			break;
		}
	}

	c->base = base;
	c->size = size;
	c->w = w;
	c->x = x;
}

bool in_cluster(ADDRINT target)
/*
*   Function to check target address is inside of
*   any memory cluster.
*/
{
	mem_cluster_t *c;

	for (unsigned i = 0; i < clusters.size(); i++)
	{
		c = &clusters[i];

		if (c->base <= target &&
			target < c->base + c->size)
		{
			return true;
		}
	}

	return false;
}

bool dump_to_file(mem_cluster_t *c, ADDRINT target)
 {
	 memory_dumper = new memory_dumper_t(target);

	 if (!memory_dumper->parse_memory())
	 {
		 fprintf(stderr, "[ERROR] parsing PE file, not possible dump\n");
		 fprintf(logfile,"[ERROR] parsing PE file, not possible dump\n");

		 delete memory_dumper;
		 return false;
	 }

	 auto* sections = memory_dumper->get_section_table_header();
	 
	 for (size_t i = 0; i < sections->get_sections().size(); i++)
	 {
		 sections->get_sections().at(i).pointerToRawData = sections->get_sections().at(i).virtualAddress;
		 sections->get_sections().at(i).sizeOfRawData = sections->get_sections().at(i).virtualSize;
	 }

	 /*
	 *	go through the APIs
	 */
	 auto* importer = memory_dumper->get_importer();

	 for (size_t i = 0; i < dll_imports.size(); i++)
	 {
		 if (dll_imports.at(i)->dll_nameA.size() != 0)
		 {
			 fprintf(stderr, "[INFO] Adding to the import DLL: %s\n", dll_imports.at(i)->dll_nameA.c_str());
			 fprintf(logfile, "[INFO] Adding to the import DLL: %s\n", dll_imports.at(i)->dll_nameA.c_str());

			 importer->ImporterAddNewDll(dll_imports.at(i)->dll_nameA.c_str());
		 }
		 else
		 {
			 fwprintf(stderr, L"[INFO] Adding to the import DLL: %S\n", dll_imports.at(i)->dll_nameW.c_str());
			 fwprintf(logfile, L"[INFO] Adding to the import DLL: %s\n", dll_imports.at(i)->dll_nameW.c_str());
			 importer->ImporterAddNewDll(dll_imports.at(i)->dll_nameW.c_str());
		 }
		 ADDRINT first_thunk = 0;

		 for (size_t j = 0; j < dll_imports.at(i)->functions.size(); j++)
		 {
			 fprintf(stderr, "[INFO] Adding to the import Function: %s\n", dll_imports.at(i)->functions.at(j).function_name.c_str());
			 fprintf(logfile, "[INFO] Adding to the import Function: %s\n", dll_imports.at(i)->functions.at(j).function_name.c_str());

			 importer->ImporterAddNewAPI(dll_imports.at(i)->functions.at(j).function_name.c_str());

			 if (first_thunk == 0)
				 first_thunk = dll_imports.at(i)->functions.at(j).function_destination;
			 else if (dll_imports.at(i)->functions.at(j).function_destination < first_thunk)
				 first_thunk = dll_imports.at(i)->functions.at(j).function_destination;
		 }

		 importer->ImporterSetNewFirstThunk((uint32_t)first_thunk);
	 }


	 fprintf(stderr, "[INFO] Dumping to file\n");
	 fprintf(logfile, "[INFO] Dumping to file\n");
	 
	 if (!memory_dumper->dump_pe_to_file())
	 {
		 fprintf(stderr, "[ERROR] Error dumping the file\n");
		 fprintf(logfile, "[ERROR] Error dumping the file\n");

		 delete memory_dumper;
		 return false;
	 }

	 delete memory_dumper;
	 return true;
 }