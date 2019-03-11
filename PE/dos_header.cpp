#include "dos_header.h"

extern FILE *logfile; // log file handler

namespace pe_parser
{
	dos_header_t::dos_header_t(ADDRINT dos_header_address)
	{
		size_t copied_size, size_to_copy = sizeof(dos_header_struct_t);
		dos_header_correct = true;

		copied_size = PIN_SafeCopy((VOID*)&dos_header, (const VOID*)dos_header_address, size_to_copy);

		if (copied_size != size_to_copy)
			dos_header_correct = false;

		if (dos_header.signature_ != mz_signature)
			dos_header_correct = false;
	}

	bool dos_header_t::check_dos_header()
	{
		return dos_header_correct;
	}

	dos_header_t::dos_header_struct_t& dos_header_t::get_dos_header()
	{
		return dos_header;
	}

	bool dos_header_t::dump_dos_header()
	{
		if (!dos_header_correct)
			return false;

		fprintf(logfile, "================== DUMP DOS HEADER ===================\n");
		fprintf(logfile, "\t+Signature: 0x%x\n", dos_header.signature_);
		fprintf(logfile, "\t+LastSize: 0x%x\n", dos_header.lastsize);
		fprintf(logfile, "\t+nBlocks: 0x%x\n", dos_header.nblocks);
		fprintf(logfile, "\t+nReloc: 0x%x\n", dos_header.nreloc);
		fprintf(logfile, "\t+hdrsize: 0x%x\n", dos_header.hdrsize);
		fprintf(logfile, "\t+minalloc: 0x%x\n", dos_header.minalloc);
		fprintf(logfile, "\t+maxalloc: 0x%x\n", dos_header.maxalloc);
		fprintf(logfile, "\t+ss_pointer: 0x%x\n", dos_header.ss_pointer);
		fprintf(logfile, "\t+sp_pointer: 0x%x\n", dos_header.sp_pointer);
		fprintf(logfile, "\t+checksum: 0x%x\n", dos_header.checksum);
		fprintf(logfile, "\t+ip_pointer: 0x%x\n", dos_header.ip_pointer);
		fprintf(logfile, "\t+cs_pointer: 0x%x\n", dos_header.cs_pointer);
		fprintf(logfile, "\t+relocpos: 0x%x\n", dos_header.relocpos);
		fprintf(logfile, "\t+noverlay: 0x%x\n", dos_header.noverlay);
		fprintf(logfile, "\t+oem_id: 0x%x\n", dos_header.oem_id);
		fprintf(logfile, "\t+opem_info: 0x%x\n", dos_header.oem_info);
		fprintf(logfile, "\t+e_lfanew: 0x%x\n", dos_header.e_lfanew);

		return true;
	}
}