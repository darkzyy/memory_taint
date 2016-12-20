//
//  Jonathan Salwan - Copyright (C) 2013-08
//
//  http://shell-storm.org
//  http://twitter.com/JonathanSalwan
//
//  Note: Example 2 - http://shell-storm.org/blog/Taint-analysis-with-Pin/
//        Spread the taint in memory and registers.
//

#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <list>
#include "uthash.h"

#define HWaddr UINT32

struct TaintNode {
    HWaddr addressTainted;
    UT_hash_handle hh;
};

TaintNode *map = NULL;

std::list<REG> regsTainted;

INT32 Usage()
{
    cerr << "Ex 2" << endl;
    return -1;
}

bool checkAlreadyRegTainted(REG reg)
{
    list<REG>::iterator i;

    for(i = regsTainted.begin(); i != regsTainted.end(); i++){
        if (*i == reg){
            return true;
        }
    }
    return false;
}

VOID removeMemTainted(HWaddr addr, int nbytes)
{
    HWaddr addr_start = addr;
    for (int i = 0; i < nbytes; i++) {
        addr = addr_start + i;
        TaintNode *tn = NULL;
        HASH_FIND_INT( map, &addr, tn );
        if (tn != NULL) {
            HASH_DEL( map, tn );
            delete tn;
            std::cout << std::hex << "\t\t\t" << addr
                << " is now freed" << std::endl;
        }
    }
}

VOID addMemTainted(HWaddr addr, int nbytes)
{
    HWaddr addr_start = addr;
    for (int i = 0; i < nbytes; i++) {
        addr = addr_start + i;
        TaintNode *tn;
        HASH_FIND_INT( map, &addr, tn );
        if (tn == NULL) {
            TaintNode *t = new TaintNode;
            HASH_ADD_INT( map, addressTainted, t);
            std::cout << std::hex << "\t\t\t" << addr
                << " is now tainted" << std::endl;
        }
    }
}

bool taintReg(REG reg)
{
    if (checkAlreadyRegTainted(reg) == true){
        std::cout << "\t\t\t" << REG_StringShort(reg) << " is already tainted"
            << std::endl;
        return false;
    }

    switch(reg){

        case REG_EAX:  regsTainted.push_front(REG_EAX);
        case REG_AX:   regsTainted.push_front(REG_AX);
        case REG_AH:   regsTainted.push_front(REG_AH);
        case REG_AL:   regsTainted.push_front(REG_AL);
                       break;

        case REG_EBX:  regsTainted.push_front(REG_EBX);
        case REG_BX:   regsTainted.push_front(REG_BX);
        case REG_BH:   regsTainted.push_front(REG_BH);
        case REG_BL:   regsTainted.push_front(REG_BL);
                       break;

        case REG_ECX:  regsTainted.push_front(REG_ECX);
        case REG_CX:   regsTainted.push_front(REG_CX);
        case REG_CH:   regsTainted.push_front(REG_CH);
        case REG_CL:   regsTainted.push_front(REG_CL);
                       break;

        case REG_EDX:  regsTainted.push_front(REG_EDX);
        case REG_DX:   regsTainted.push_front(REG_DX);
        case REG_DH:   regsTainted.push_front(REG_DH);
        case REG_DL:   regsTainted.push_front(REG_DL);
                       break;

        case REG_EDI:  regsTainted.push_front(REG_EDI);
        case REG_DI:   regsTainted.push_front(REG_DI);
                       break;

        case REG_ESI:  regsTainted.push_front(REG_ESI);
        case REG_SI:   regsTainted.push_front(REG_SI);
                       break;

        default:
                       std::cout << "\t\t\t" << REG_StringShort(reg)
                           << " can't be tainted" << std::endl;
                       return false;
    }
    std::cout << "\t\t\t" << REG_StringShort(reg) << " is now tainted"
        << std::endl;
    return true;
}

bool removeRegTainted(REG reg)
{
    switch(reg){

        case REG_EAX:  regsTainted.remove(REG_EAX);
        case REG_AX:   regsTainted.remove(REG_AX);
        case REG_AH:   regsTainted.remove(REG_AH);
        case REG_AL:   regsTainted.remove(REG_AL);
                       break;

        case REG_EBX:  regsTainted.remove(REG_EBX);
        case REG_BX:   regsTainted.remove(REG_BX);
        case REG_BH:   regsTainted.remove(REG_BH);
        case REG_BL:   regsTainted.remove(REG_BL);
                       break;

        case REG_ECX:  regsTainted.remove(REG_ECX);
        case REG_CX:   regsTainted.remove(REG_CX);
        case REG_CH:   regsTainted.remove(REG_CH);
        case REG_CL:   regsTainted.remove(REG_CL);
                       break;

        case REG_EDX:  regsTainted.remove(REG_EDX);
        case REG_DX:   regsTainted.remove(REG_DX);
        case REG_DH:   regsTainted.remove(REG_DH);
        case REG_DL:   regsTainted.remove(REG_DL);
                       break;

        case REG_EDI:  regsTainted.remove(REG_EDI);
        case REG_DI:   regsTainted.remove(REG_DI);
                       break;

        case REG_ESI:  regsTainted.remove(REG_ESI);
        case REG_SI:   regsTainted.remove(REG_SI);
                       break;

        default:
                       return false;
    }
    std::cout << "\t\t\t" << REG_StringShort(reg) << " is now freed" << std::endl;
    return true;
}

VOID ReadMem(HWaddr pc, std::string insDis, REG reg_r, REG reg_w,
        int numOperand, HWaddr memOp, int nbytes)
{
    std::cout << "Processing: [" << pc << "] as memRead: " << insDis
        << "bytes=" << nbytes << " Reading " << memOp << std::endl;

    list<TaintNode>::iterator i;
    HWaddr addr_start = memOp;
    HWaddr addr;


    if (numOperand != 2)
        return;

    for (int i = 0; i < nbytes; i++) {
        addr = addr_start + i;
        TaintNode *tn;
        HASH_FIND_INT( map, &addr, tn );
        if (tn != NULL) {
            std::cout << std::hex << "[READ in " << addr << "]\t"
                << pc << ": " <<insDis << std::endl;
            taintReg(reg_r);
            return ;
        }
    }

    if (checkAlreadyRegTainted(reg_r)){
        std::cout << std::hex << "[READ in " << addr_start << "]\t"
            << pc << ": " <<insDis << std::endl;
        removeRegTainted(reg_r);
    }
}

VOID WriteMem(HWaddr pc, std::string insDis, REG reg_r, REG reg_w,
        int numOperand, HWaddr memOp, int nbytes)
{
    // std::cout << "Processing: [" << pc << "] as memWrite: " <<insDis << std::endl;

    list<TaintNode>::iterator i;
    HWaddr addr_start = memOp;
    HWaddr addr;
    reg_r = reg_w;


    //std::cout << pc << endl;
    if (pc == 0x80484c1) {
        REG reg_a = REG_AL;
        std::cout << "Tainting init Reg!\n";
        taintReg(reg_a);
        addMemTainted(addr, nbytes);
        return;
    }


    if (numOperand != 2)
        return;

    for (int i = 0; i < nbytes; i++) {
        addr = addr_start + i;
        TaintNode *tn;
        HASH_FIND_INT( map, &addr, tn );
        if (tn != NULL) {
            std::cout << std::hex << "[WRITE in " << addr << "]\t"
                << pc << ": " <<insDis << std::endl;
            if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
                removeMemTainted(addr, nbytes);
            return ;
        }
    }

    if (checkAlreadyRegTainted(reg_r)){
        std::cout << std::hex << "[WRITE in " << addr_start << "]\t"
            << pc << ": " <<insDis << std::endl;
        for (int i = 0; i < nbytes; i++) {
            addr = addr_start + i;
            addMemTainted(addr, nbytes);
        }
    }
}

VOID spreadRegTaint(HWaddr pc, std::string insDis, REG reg_r, REG reg_w,
        int numOperand)
{
    //std::cout << "Processing: [" << pc << "] as R2R: " << insDis << std::endl;


    if (numOperand != 2) {
        // std::cout << "Ignored: [" << pc << "]" << insDis << std::endl;
        return;
    }


    /*
    if (REG_valid(reg_w)) {
        cout << REG_StringShort(reg_w) << " Tainted? : "
            << checkAlreadyRegTainted(reg_w) <<endl;
    }
    if (REG_valid(reg_r)) {
        cout << REG_StringShort(reg_r) << " Tainted? : "
            << checkAlreadyRegTainted(reg_r) <<endl;
    }
    */

    if (REG_valid(reg_w)){
        if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) ||
                    !checkAlreadyRegTainted(reg_r))){
            std::cout << "[SPREAD]\t\t" << pc << ": "
                << insDis << std::endl;
            std::cout << "\t\t\toutput: "<< REG_StringShort(reg_w)
                << " | input: "
                << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant")
                << std::endl;
            removeRegTainted(reg_w);
        }
        else if (!checkAlreadyRegTainted(reg_w)
                && checkAlreadyRegTainted(reg_r)){

            std::cout << "[SPREAD]\t\t" << pc << ": "
                << insDis << std::endl;
            std::cout << "\t\t\toutput: " << REG_StringShort(reg_w)
                << " | input: "<< REG_StringShort(reg_r) << std::endl;
            taintReg(reg_w);
        }
    }
}

VOID Instruction(INS ins, VOID *v)
{
    if (INS_IsNop(ins)) {
        std::cout << "Not Processed: [" << IARG_INST_PTR << "]"
            << INS_Disassemble(ins) << std::endl;
        return;
    }
    if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 0)
            && INS_OperandIsReg(ins, 0)){
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
                IARG_UINT32, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandReg(ins, 0),
                IARG_UINT32, INS_OperandReg(ins, 1),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYOP_EA, 0,
                IARG_UINT32, INS_OperandWidth(ins, 1)/8,
                IARG_END);
    }
    else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)){
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
                IARG_UINT32, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_OperandReg(ins, 0),
                IARG_UINT32, INS_OperandReg(ins, 1),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_MEMORYOP_EA, 0,
                IARG_UINT32, INS_OperandWidth(ins, 1)/8,
                IARG_END);
    }
    else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
        INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
                IARG_UINT32, INS_Address(ins),
                IARG_PTR, new string(INS_Disassemble(ins)),
                IARG_UINT32, INS_RegR(ins, 0),
                IARG_UINT32, INS_RegW(ins, 0),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_END);
    }
}

VOID Fini(int, VOID *v)
{
    list<TaintNode>::iterator i;
    std::cout << "Tainted Memory:\n";
    TaintNode *tn;
    for (tn = map; tn != NULL; tn = (TaintNode *)tn->hh.next) {
        std::cout << "0x" << std::hex << tn->addressTainted << endl;
    }
}

int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }

    PIN_SetSyntaxIntel();
    // PIN_AddSyscallEntryFunction(Syscall_entry, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();

    return 0;
}

