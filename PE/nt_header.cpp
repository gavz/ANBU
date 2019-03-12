
#include "nt_header.h"

/************* EXTERN VARIABLES *************/
extern FILE *logfile; // log file handler


namespace pe_parser
{
	nt_header_t::nt_header_t(ADDRINT address)
	{
		size_t copied_size, size_to_copy = sizeof(nt_coff_struct_t);
		pe_header_correct = true;

		copied_size = PIN_SafeCopy((VOID*)&nt_coff_header, (const VOID*)address, size_to_copy);

		if (size_to_copy != copied_size)
			pe_header_correct = false;


		if (nt_coff_header.pe_signature != correct_pe_signature_k)
			pe_header_correct = false;
	}
	
	nt_header_t::nt_coff_struct_t& nt_header_t::get_nt_header()
	{
		return nt_coff_header;
	}

	bool nt_header_t::is_pe_header_correct()
	{
		return pe_header_correct;
	}

	bool nt_header_t::dump_nt_header()
	{
		if (!pe_header_correct)
			return false;

		fprintf(logfile, "================== DUMP NT HEADER ===================\n");
		fprintf(logfile, "\t+PE Signature: 0x%x\n", nt_coff_header.pe_signature);
		fprintf(logfile, "\t+Machine: 0x%x\n", nt_coff_header.machine);
		fprintf(logfile, "\t+Number Of Sections: 0x%x\n", nt_coff_header.numberOfSections);
		fprintf(logfile, "\t+TimeDateStamp: 0x%x\n", nt_coff_header.timeDateStamp);
		fprintf(logfile, "\t+Pointer to Symbol Table: 0x%x\n", nt_coff_header.pointerToSymbolTable);
		fprintf(logfile, "\t+Number of symbols: 0x%x\n", nt_coff_header.numberOfSymbols);
		fprintf(logfile, "\t+Size of optional header: 0x%x\n", nt_coff_header.sizeOfOptionalHeader);
		fprintf(logfile, "\t+Characteristics: 0x%x\n", nt_coff_header.characteristics);

		return true;
	}
}