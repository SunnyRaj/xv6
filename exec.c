#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "defs.h"
#include "x86.h"
#include "elf.h"

int
exec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint argc, sz, sp, ustack[3+MAXARG+1];
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pde_t *pgdir, *oldpgdir;

  // namei converts given path into inode
  begin_op();
  if((ip = namei(path)) == 0){
    end_op();
    return -1;
  }
  ilock(ip);
  pgdir = 0;

  // Check ELF header
  // if the file is smaller than the size of an elf header,
  // then it doesn't hold an elf header. (ERROR)
  if(readi(ip, (char*)&elf, 0, sizeof(elf)) < sizeof(elf))
    goto bad;
  if(elf.magic != ELF_MAGIC)
    goto bad;

  if((pgdir = setupkvm()) == 0)
    goto bad;

  // Load program into memory.
  // do this for each section of the elf file (chunk size dlineated
  // by sizeof program header)
  // allocate user virtual memory
  // load program into user virtual memory
  // in linux, run readelf -a /bin/ls and see the the offset and size
  // column program section header being loaded
  sz = 0;
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, (char*)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if((sz = allocuvm(pgdir, sz, ph.vaddr + ph.memsz)) == 0)
      goto bad;
    if(loaduvm(pgdir, (char*)ph.vaddr, ip, ph.off, ph.filesz) < 0)
      goto bad;
  }
  iunlockput(ip);
  end_op();
  ip = 0;

  // Allocate two pages at the next page boundary.
  // Make the first inaccessible.  Use the second as the user stack.
  sz = PGROUNDUP(sz);   // This is macro function that jumps to the next page boundary
  if((sz = allocuvm(pgdir, sz, sz + 2*PGSIZE)) == 0)
    goto bad;
  // this makes the inaccessible page
  clearpteu(pgdir, (char*)(sz - 2*PGSIZE));
  sp = sz;

  // Push argument strings, prepare rest of stack in ustack.
  // This code is building the stack frame of the application.
  // since argc is not passed into this function, to find the max
  // num of args, we need to step through the argv string until the
  // item returned is NULL or the end of the string.
  // This means that we have found all of the arguments.
  // Next, we need to copy each argument into the stack and keep
  // references to it in a local stack.  Once this is done, we can
  // set the stack pointer to point to the first argument on the stack.
  // now, we can put the return value and the total number of args onto our
  // local stack.  Then, we must prepare local stack for the copy into the
  // real stack.  Next, we adjust the real stack pointer to make
  // room for our local stack and then we copy our stack that contains
  // pointers to each argument onto the stack.
  // We need this for quick lookup of each argument -- without the poitners
  // we can't efficiently get the args back.  we also need the
  // the total number of arguments to make sure that we are growing the
  // stack properly.
  // think about this: int main(int argc, char **argv);
  // this code defends why we need a double pointer to a char.
  // we are giving an array of char *.
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    // explain of ~3 in following line:
        // to make memory align with 4 bits, we the two lower order bit
        // which are the oly two bits that aren't divisibile by 4.
        // this is to keep the compiler aligned with the system
    sp = (sp - (strlen(argv[argc]) + 1)) & ~3;
    if(copyout(pgdir, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[3+argc] = sp;
  }
  ustack[3+argc] = 0;

  ustack[0] = 0xffffffff;  // fake return PC
  ustack[1] = argc;
  // This is getting the real stack ready for the copy
  // of the local stack, ustack[]
  ustack[2] = sp - (argc+1)*4;  // argv pointer

  // this is moving the stack pointer to the location of first argument.
  sp -= (3+argc+1) * 4;
  // This is copying the ustack[] into the real stack
  if(copyout(pgdir, sp, ustack, (3+argc+1)*4) < 0)
    goto bad;
  // done buildng the stack frame

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(proc->name, last, sizeof(proc->name));

  // Commit to the user image.
  oldpgdir = proc->pgdir;
  proc->pgdir = pgdir;
  proc->sz = sz;
  proc->tf->eip = elf.entry;  // main
  proc->tf->esp = sp;
  switchuvm(proc);
  freevm(oldpgdir);
  return 0;

 bad:
  if(pgdir)
    freevm(pgdir);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}
