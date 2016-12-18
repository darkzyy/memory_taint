#include "pin.H"
#include "control_manager.H"
#include "portability.H"
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>

typedef VOID(* LEVEL_PINCLIENT::SYSCALL_ENTRY_CALLBACK)(THREADID threadIndex,
        CONTEXT *ctxt,
        SYSCALL_STANDARD std,
        VOID *v);

typedef VOID(* LEVEL_PINCLIENT::SYSCALL_EXIT_CALLBACK)(THREADID threadIndex,
        CONTEXT *ctxt,
        SYSCALL_STANDARD std,
        VOID *v);

VOID LEVEL_PINCLIENT::PIN_AddSyscallEntryFunction(SYSCALL_ENTRY_CALLBACK fun, VOID *val);
VOID LEVEL_PINCLIENT::PIN_AddSyscallExitFunction(SYSCALL_EXIT_CALLBACK fun, VOID *val);

typedef VOID(* LEVEL_PINCLIENT::INS_INSTRUMENT_CALLBACK)(INS ins, VOID *v);

VOID LEVEL_PINCLIENT::INS_AddInstrumentFunction(INS_INSTRUMENT_CALLBACK fun, VOID *val);

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

int main(int argc, char *argv[])
{
    /* Init Pin arguments */
    if(PIN_Init(argc, argv)){
        return Usage();
    }

    /* Add the syscall handler */
    PIN_AddSyscallEntryFunction(Syscall_entry, 0);

    /* Start the program */
    PIN_StartProgram();

    return 0;
}
