#include "pin.H"
#include <iostream>
#include <list>
#include <sys/syscall.h>

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

UINT64 ins_count = 0;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */


/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr <<
        "This tool prints out the number of dynamic instructions executed to stderr.\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* area of bytes tainted */
struct range
{
  UINT64 start;
  UINT64 end;
};

std::list<struct range> bytesTainted;

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
  struct range taint;

  /* If the syscall is read take the branch */
  if (PIN_GetSyscallNumber(ctx, std) == __NR_read){

      /* Get the second argument */
      taint.start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));

      /* Get the third argument */
      taint.end   = taint.start + static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));

      /* Add this area in our tainted bytes list */
      bytesTainted.push_back(taint);

      /* Just display information */
      std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x" << taint.start \
      << " to 0x" << taint.end << " (via read)"<< std::endl;
  }
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    

    PIN_AddSyscallEntryFunction(Syscall_entry, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}

