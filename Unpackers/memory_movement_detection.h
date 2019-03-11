#pragma once

#ifndef MEMORY_MOVEMENT_DETECTION_H
#define MEMORY_MOVEMENT_DETECTION_H

#include "common.h"
#include "generic_instrumentation.h"

// PE Headers
#include "memory_dumper.h"

/***
 *  Structure to track memory activity
 *  we will log written or executed bytes
 *  from memory. For that reason
 *  we record the type of memory access (write or execute)
 *  and the value of written bytes
 */
typedef struct mem_access
{
	mem_access() : w(false), x(false), val(0) {}
	mem_access(bool ww, bool xx, unsigned char v) : w(ww), x(xx), val(v) {}
	bool w;
	bool x;
	unsigned char val;
} mem_access_t;

/***
 *  In the unpacking process, we will need to cluster
 *  adjacent memory bytes to know which memory dump.
 *  For that is this structure, we will record the
 *  base address, the size and the access permission
 */
typedef struct mem_cluster
{
	mem_cluster() : base(0), size(0), w(false), x(false) {}
	mem_cluster(ADDRINT b, unsigned long s, bool ww, bool xx)
		: base(b), size(s), w(ww), x(xx) {}
	ADDRINT         base;
	unsigned long   size;
	bool            w;
	bool            x;
} mem_cluster_t;


/******************* unpacker funcionts *******************/
void fini(INT32 code, void *v);

void instrument_mem_cflow(INS ins, void *v);
void queue_memwrite(ADDRINT addr);
void log_memwrite(UINT32 size);
void check_indirect_ctransfer(ADDRINT ip, ADDRINT target);
void mem_to_file(mem_cluster_t *c, ADDRINT entry);
void set_cluster(ADDRINT target, mem_cluster_t *c);
bool in_cluster(ADDRINT target);
bool dump_to_file(mem_cluster_t *c, ADDRINT target);

#endif // !MEMORY_MOVEMENT_DETECTION_H
