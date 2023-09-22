#### Issue to be created

## Issue Description

I write the architectural verification test for SV48, which you can find [here](https://github.com/YazanHussnain-10x/su21-lab-starter/tree/main/SV48_tests). I used the sail as my reference model. When I checked the sail's log for the test, I noticed that when address translation is enabled, the page table is correctly accessed for the first instruction. However, for the next instruction, which is on the same page, the page table should not be accessed because the TLB should be updated with the translation info as per the specs. The translation is expected to be found in the TLB. Unfortunately, in the case of SV48, the TLB is not accessed. Instead, for every instruction, the sail is accessing the page table, which should not be happening.
I also write a test for SV39, TLB in that test is working as expected.

Here is the part of the log when address translation is enabled:
``` C
[486] [M]: 0x008000000000087C (0x341494F3) csrrw s1, mepc, s1
CSR mepc -> 0x0000000000000000
CSR mepc <- 0x0000020000000884 (input: 0x0000020000000884)
x9 <- 0x0000000000000000

mem[X,0x0080000000000880] -> 0x0073
mem[X,0x0080000000000882] -> 0x3020
[487] [M]: 0x0080000000000880 (0x30200073) mret
CSR mstatus <- 0x0000000A00000080
ret-ing from M to S

mem[R,0x0080000000006020] -> 0x00200000000000CF // Page Table Accessed
mem[X,0x0080000000000884] -> 0x0293
mem[R,0x0080000000006020] -> 0x00200000000000CF // Page Table Accessed Again
mem[X,0x0080000000000886] -> 0x0050
[488] [S]: 0x0000020000000884 (0x00500293) addi t0, zero, 5
x5 <- 0x0000000000000005

mem[R,0x0080000000006020] -> 0x00200000000000CF // Page Table Accessed Again
mem[X,0x0080000000000888] -> 0x9293
mem[R,0x0080000000006020] -> 0x00200000000000CF // Page Table Accessed Again
mem[X,0x008000000000088A] -> 0x0272
[489] [S]: 0x0000020000000888 (0x02729293) slli t0, t0, 39
x5 <- 0x0000028000000000
```

As you can see, the page table is accessed, and the PTEs at all levels (in this case only one page table is used) are read again for the second instruction after mret.

## Required Changes

Add support of TLB for SV48 address translation scheme.

## Current Status

Currently TLB for SV48 is not working.

________________________________________________________________


#### PR to be created

## Pull Request

This PR is the solution for issue 21 opened in sail-riscv on Sep 21st, 2023.

## Issue

TLB is not looked up for translation in the SV48 address translation scheme.

## Reason of the Issue

The code that was looked up in the TLB is not present, and the TLB is also not updated with the translation information when a PTE is found in the page table within the function 'translate48' in riscv_vmem_sv48.sail file.

## Solution

The 'translate48' function is updated to look up in the TLB first before accessing the page table. Additionally, if there is a TLB miss and the page table is accessed, then the TLB is updated with the translation information when the correct PTE is found in the page table.

``` C
val translate48 : (asid64, paddr64, vaddr48, AccessType(ext_access_type), Privilege, bool, bool, nat, ext_ptw) -> TR_Result(paddr64, PTW_Error) effect {rreg, wreg, wmv, wmvt, escape, rmem, rmemt}
function translate48(asid, ptb, vAddr, ac, priv, mxr, do_sum, level, ext_ptw) = {
  match lookup_TLB48(asid, vAddr) {
    Some(idx, ent) => {
/*    print("translate48: TLB48 hit for " ^ BitStr(vAddr)); */
      let  pte = Mk_SV48_PTE(ent.pte);
      let  ext_pte = pte.Ext();
      let  pteBits = Mk_PTE_Bits(pte.BITS());
      match checkPTEPermission(ac, priv, mxr, do_sum, pteBits, ext_pte, ext_ptw) {
        PTE_Check_Failure(ext_ptw, ext_ptw_fail) => { TR_Failure(ext_get_ptw_error(ext_ptw_fail), ext_ptw) },
        PTE_Check_Success(ext_ptw) => {
          match update_PTE_Bits(pteBits, ac, ext_pte) {
            None()           => TR_Address(ent.pAddr | EXTZ(vAddr & ent.vAddrMask), ext_ptw),
            Some(pbits, ext) => {
              if not(plat_enable_dirty_update())
              then {
                /* pte needs dirty/accessed update but that is not enabled */
                TR_Failure(PTW_PTE_Update(), ext_ptw)
              } else {
                /* update PTE entry and TLB */
                n_pte = update_BITS(pte, pbits.bits());
                n_pte = update_Ext(n_pte, ext);
                n_ent : TLB48_Entry = ent;
                n_ent.pte = n_pte.bits();
                write_TLB48(idx, n_ent);
                /* update page table */
                match mem_write_value_priv(EXTZ(ent.pteAddr), 8, n_pte.bits(), Supervisor, false, false, false) {
                  MemValue(_)     => (),
                  MemException(e) => internal_error(__FILE__, __LINE__, "invalid physical address in TLB")
                };
                TR_Address(ent.pAddr | EXTZ(vAddr & ent.vAddrMask), ext_ptw)
              }
            }
          }
        }
      }
    },
    None() => {
      match walk48(vAddr, ac, priv, mxr, do_sum, ptb, level, false, ext_ptw) {
        PTW_Failure(f, ext_ptw) => TR_Failure(f, ext_ptw),
        PTW_Success(pAddr, pte, pteAddr, level, global, ext_ptw) => {
          match update_PTE_Bits(Mk_PTE_Bits(pte.BITS()), ac, pte.Ext()) {
            None() => {
              add_to_TLB48(asid, vAddr, pAddr, pte, pteAddr, level, global);
              TR_Address(pAddr, ext_ptw)
            },
            Some(pbits, ext) =>
              if not(plat_enable_dirty_update())
              then {
                /* pte needs dirty/accessed update but that is not enabled */
                TR_Failure(PTW_PTE_Update(), ext_ptw)
              } else {
                w_pte : SV48_PTE = update_BITS(pte, pbits.bits());
    w_pte : SV48_PTE = update_Ext(w_pte, ext);
                match mem_write_value_priv(EXTZ(pteAddr), 8, w_pte.bits(), Supervisor, false, false, false) {
                  MemValue(_) => {
                    add_to_TLB48(asid, vAddr, pAddr, w_pte, pteAddr, level, global);
                    TR_Address(pAddr, ext_ptw)
                  },
                  MemException(e) => {
                    /* pte is not in valid memory */
                    TR_Failure(PTW_Access(), ext_ptw)
                  }
                }
              }
          }
        }
      }
    }
  }
}

```

The same test is run which mentioned in the issue 21 the log is now look like this:

``` C
[486] [M]: 0x008000000000087C (0x341494F3) csrrw s1, mepc, s1
CSR mepc -> 0x0000000000000000
CSR mepc <- 0x0000020000000884 (input: 0x0000020000000884)
x9 <- 0x0000000000000000

mem[X,0x0080000000000880] -> 0x0073
mem[X,0x0080000000000882] -> 0x3020
[487] [M]: 0x0080000000000880 (0x30200073) mret
CSR mstatus <- 0x0000000A00000080
ret-ing from M to S

mem[R,0x0080000000006020] -> 0x00200000000000CF // Page Table Accessed
mem[X,0x0080000000000884] -> 0x0293
mem[X,0x0080000000000886] -> 0x0050
[488] [S]: 0x0000020000000884 (0x00500293) addi t0, zero, 5
x5 <- 0x0000000000000005

mem[X,0x0080000000000888] -> 0x9293
mem[X,0x008000000000088A] -> 0x0272
[489] [S]: 0x0000020000000888 (0x02729293) slli t0, t0, 39
x5 <- 0x0000028000000000
```

For SLLI the instruction page table is not accessed because translation information is found in the TLB.
