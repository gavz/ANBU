/*
*   Compile: make PIN_ROOT="<path_to_pin>"
*/
#include "unpacker.h"


FILE*				logfile; // log file handler
 /*
 *   KNOB class to create arguments with PIN
 *   on this case, we will create an argument
 *   string for the user if wants to save
 *   logs in a file.
 */
KNOB<string>		KnobLogFile(
			KNOB_MODE_WRITEONCE,
			"pintool",
			"l", // command accepted (-l)
			"unpacker.log", // value of the command, log file name
			"log file"
);
/*
*	argument to activate the Debug mode
*/
KNOB<string>		KnobDebugFile(
			KNOB_MODE_WRITEONCE,
			"pintool",
			"d", // command accepted (-d)
			"false",
			"start debug mode"
);


/*
*	PIN Exception handler function
*/
EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
	EXCEPTION_CODE c = PIN_GetExceptionCode(pExceptInfo);
	EXCEPTION_CLASS cl = PIN_GetExceptionClass(c);

	fprintf(stderr, "Exception class: 0x%x\n", (unsigned int)cl);
	fprintf(logfile, "Exception class: 0x%x\n", (unsigned int)cl);

	fprintf(stderr,"Exception string: %s\n", PIN_ExceptionToString(pExceptInfo).c_str());
	fprintf(logfile, "Exception string: %s\n", PIN_ExceptionToString(pExceptInfo).c_str());

	return EHR_UNHANDLED;
}

int main(int argc, char *argv[])
{
	fprintf(stderr, "+--<<< PIN-Pong by F9 >>>>--+\n");
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

	if (strcmp(KnobDebugFile.Value().c_str(), "true") == 0)
	{
		DEBUG_MODE debug;
		debug._type		= DEBUG_CONNECTION_TYPE_TCP_SERVER;
		debug._options	= DEBUG_MODE_OPTION_STOP_AT_ENTRY;
		PIN_SetDebugMode(&debug);
	}

	// open log file to append
	fprintf(stderr, "[INFO] File name: %s\n", KnobLogFile.Value().c_str());
	logfile = fopen(KnobLogFile.Value().c_str(), "w");
	if (!logfile)
	{
		fprintf(stderr, "[ERROR] failed to open '%s'\n", KnobLogFile.Value().c_str());
		return 1;
	}

	PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);

	fprintf(logfile, "+--<<< PIN-Pong by F9 >>>>--+\n");

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
	fprintf(stderr, "\t+ -d true (OPTIONAL): start debug mode\n");
	fprintf(stderr, "\n");
}