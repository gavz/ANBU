/*
*   Compile: make PIN_ROOT="<path_to_pin>"
*/
#include "unpacker.h"


FILE *logfile; // log file handler
 /*
 *   KNOB class to create arguments with PIN
 *   on this case, we will create an argument
 *   string for the user if wants to save
 *   logs in a file.
 */
KNOB<string> KnobLogFile(
	KNOB_MODE_WRITEONCE,
	"pintool",
	"l", // command acepted (-l)
	"unpacker.log", // value of the command, log file name
	"log file"
);

int main(int argc, char *argv[])
{
	fprintf(stderr, "+--<<<Generic Unpacker by F9>>>>--+\n");
	/*
	*	As we will use symbols...
	*/
	PIN_InitSymbols();
	/*
	*   Function to initialize the Pintool
	*   always called before almost any other PIN
	*   function (only PIN_InitSymbols can be before)
	*/
	if (PIN_Init(argc, argv))
	{
		usage();
		return 1;
	}

	// open log file to append
	fprintf(stderr, "[INFO] File name: %s\n", KnobLogFile.Value().c_str());
	logfile = fopen(KnobLogFile.Value().c_str(), "w");
	if (!logfile)
	{
		fprintf(stderr, "[ERROR] failed to open '%s'\n", KnobLogFile.Value().c_str());
		return 1;
	}
	fprintf(logfile, "+--<<<Generic Unpacker by F9>>>>--+\n");

	fprintf(stderr, "------ unpacking binary ------\n");
	fprintf(logfile, "------ unpacking binary ------\n");

	enum_syscalls();

	init_common_syscalls();

	syscall_t sc[256] = { 0 };
	/*
	*	Add instrumentation function for Syscalls entry and exit
	*/
	PIN_AddSyscallEntryFunction(&syscall_entry, &sc);
	PIN_AddSyscallExitFunction(&syscall_exit, &sc);


	/*
	*   Add instrumentation function at Instruction tracer level
	*   in opposite to TRACE instrumentation, this goes to an
	*   instruction granularity.
	*/
	INS_AddInstrumentFunction(instrument_mem_cflow, NULL);

	/*
	*   Add the fini function
	*/
	PIN_AddFiniFunction(fini, NULL);

	/*
	*	Add instrumentation for IMG loading.
	*/
	IMG_AddInstrumentFunction(get_addresses_from_images, NULL);

	/*
	*   RUN the program and never return
	*/
	PIN_StartProgram();

	return 1;
}


void usage()
{
	fprintf(stderr, "[ERROR] Parameters error, please check next help line(s)\n");
	fprintf(stderr, "pin -t <pintool_path> [-l <logname>] -- application\n");
	fprintf(stderr, "Commands: \n");
	fprintf(stderr, "\t+ -t <pintool_path> (MANDATORY): necessary flag for PIN to specify a pintool\n");
	fprintf(stderr, "\t+ -l <logname> (OPTIONAL): specify name for a log file\n");
	fprintf(stderr, "\n");
}