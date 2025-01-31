#include <stdio.h>  // Standard input and output
#include <stdlib.h> // Memory allocation and process-related functions
#include <unistd.h> // Unix system-related functions
#include <sys/types.h>  // System data types
#include <sys/ptrace.h> // Process tracing
#include <sys/user.h>   // Structures defining process registers, memory, and stack information
#include <sys/wait.h>   // Waiting for child process termination
#include <string.h> // String handling
#include <fcntl.h>  // File control-related functions
#include <sys/mman.h>  // Memory mapping functions
#include <errno.h>  // Error codes
#include <gelf.h>   // ELF file handling
#include <libelf.h> // ELF file handling
#include <capstone/capstone.h>  // Disassembler

long int ep_offset; // Entry point
long int base_address = 0;  // Base address in the process

struct user_regs_struct regs;   // Register structure
struct user_regs_struct saved_regs; // Structure to track changes in registers

size_t code_count = 0;  // Number of disassembled instructions in the .text section

cs_insn *insn;  // Structure to store disassembled data

int bp_count = 0;   // Number of breakpoints
int conti_count = 0;    // Number of continue operations

void* entry_point; // Process entry point

struct 
{
    void* address;
    long int save;
}bp[10];    // Breakpoint structure

struct
{
    unsigned long int address;
    char function_name[256];
    int size;
    char mnemonic[32];
    char op_str[256];
    int function_size;
}code[100000];  // Structure to store disassembled code from the .text section

struct
{
    char name[256];
    unsigned long int address;
}function[1000];    // Structure to store function list

// Base address parsing
void get_base_address(pid_t pid) 
{
    char maps_path[64]; // Path to /proc/pid/maps file
    FILE *maps_file;
    char line[256];

    // Generate /proc/<PID>/maps file path based on PID
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    // Open the maps file
    maps_file = fopen(maps_path, "r");
    if (maps_file == NULL) {
        perror("fopen");
        exit(1);
    }

    // Read the first line
    if (fgets(line, sizeof(line), maps_file)) {
        // Parse the first address
        char *token = strtok(line, "-");
        if (token) {
            base_address = strtoul(token, NULL, 16); // Convert to hexadecimal
        }
    } else {
        perror("fgets");
        exit(1);
    }

    fclose(maps_file);
}

// Parse data from ELF file
void elf_parsing(pid_t pid, char *filename)
{
    get_base_address(pid);  // Parse the base address of the process
    
    printf("\033[1;32mbase address\033[0m of process \033[1;35m%s\033[0m : \033[1;31m0x%lx\033[0m\n", filename, base_address);
    
    int fd = open(filename, O_RDONLY);

    if (fd == -1) {
        perror("Error opening file");
    }
    
    if (elf_version(EV_CURRENT) == EV_NONE) {   // Initialize ELF file version
        fprintf(stderr, "Error initializing libelf: %s\n", elf_errmsg(-1));
        close(fd);
        exit(1);
    }

    
    int code_sum = 0;

    // Read the ELF structure
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL); // Create ELF structure using elf_begin
    if (elf == NULL) {
        fprintf(stderr, "Error reading ELF: %s\n", elf_errmsg(-1));
        close(fd);
        exit(1);
    }

    //--------------------------
    // Offset parsing

    // Get ELF header
    GElf_Ehdr header;   // Structure to store ELF header
    if (gelf_getehdr(elf, &header) == NULL) {   // Get ELF header information and store it in the header structure
        fprintf(stderr, "Error getting ELF header: %s\n", elf_errmsg(-1));
        elf_end(elf);
        close(fd);
        exit(1);
    }

    ep_offset = header.e_entry; // Read the e_entry field from the ELF header and store the entry point

    entry_point = (void*) (ep_offset + base_address);
    printf("\033[0;32mentry point\033[0m : \033[0;31m%p\033[0m\n", entry_point);

    //--------------------------
    // Code disassemble

    Elf_Scn *section = NULL; 
    const char *name;   // Store section name
    size_t strtab_index;    // Index of the section string table
    GElf_Shdr shdr; // Structure to store section header information
    csh handle; // Capstone disassembler handle

    // Get the section string table index
    if (elf_getshdrstrndx(elf, &strtab_index) != 0) {   // elf_getshdrstrndx: Search for section string table
        fprintf(stderr, "Failed to get section string table index\n");
        elf_end(elf);
        close(fd);
        return;
    }

    // Find the .text section
    while ((section = elf_nextscn(elf, section)) != NULL) { // elf_nextscn: Return the next section
        if (!gelf_getshdr(section, &shdr)) { // gelf_getshdr: Explore the section header
            fprintf(stderr, "Failed to get section header\n");
            continue;
        }

        name = elf_strptr(elf, strtab_index, shdr.sh_name); // elf_strptr: Search for the string pointer in the string table
        if (name && strcmp(name, ".text") == 0) {   // Compare the name field in the section header with ".text"
            break;
        }
    }

    if (!section) {
        fprintf(stderr, "Section '.text' not found in ELF file\n");
        elf_end(elf);
        close(fd);
        return;
    }

    // Read section data
    Elf_Data *data = elf_getdata(section, NULL);    // Elf_Data: Structure to store the actual section data, elf_getdata: Get the section data 
    if (!data) {
        fprintf(stderr, "Failed to get section data\n");
        elf_end(elf);
        close(fd);
        return;
    }

    // Disassemble the code
    // Initialize Capstone
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {   // Initialize Capstone disassembler
        fprintf(stderr, "Failed to initialize Capstone\n");
        elf_end(elf);
        close(fd);
        return;
    }

    code_count = cs_disasm(handle, data->d_buf, data->d_size, shdr.sh_addr, 0, &insn); // Disassemble the code

    if (code_count > 0) {
        printf("Disassembled \033[1;32m%zu\033[0m instructions from section '\033[1;33m.text\033[0m':\n", code_count);
        for (int i = 0; i < (int)code_count; i++) {
            code[i].address = insn[i].address + base_address;
            code[i+1].size = insn[i].size;
            strcpy(code[i].mnemonic, insn[i].mnemonic);
            strcpy(code[i].op_str, insn[i].op_str); // Store in code structure
        }
        cs_free(insn, code_count);  // Free the memory allocated by Capstone
    } else {
        fprintf(stderr, "Failed to disassemble section '.text'\n");
    }

    //--------------------------
    // Function parsing
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {   // elf_getshdrstrndx: Search for the section string table
        fprintf(stderr, "Failed to get section string table index: %s\n", elf_errmsg(-1));
        elf_end(elf);
        return;
    }

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            fprintf(stderr, "Failed to get section header: %s\n", elf_errmsg(-1));
            continue;
        }

        // Search for symbol table
        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) { // Search static or dynamic symbol table
            Elf_Data *data = elf_getdata(scn, NULL);    // Get data from the section
            if (!data) {
                fprintf(stderr, "Failed to get section data: %s\n", elf_errmsg(-1));
                continue;
            }

            size_t num_symbols = shdr.sh_size / shdr.sh_entsize;    // Calculate the number of symbols by dividing the section size by the symbol entry size

            for (size_t i = 0; i < num_symbols; i++) {  
                GElf_Sym sym;   // Structure to store symbol information
                if (!gelf_getsym(data, i, &sym)) {  // Get the i-th symbol from the symbol table
                    fprintf(stderr, "Failed to get symbol: %s\n", elf_errmsg(-1));
                    continue;
                }
                
                const char *sym_name = elf_strptr(elf, shdr.sh_link, sym.st_name);

                if (GELF_ST_TYPE(sym.st_info) == STT_FUNC) {    // Only process function symbols
                    strcpy(function[i].name, sym_name); // Store function address and name in the function structure
                    function[i].address = sym.st_value + base_address;
                    for (int j = 0; j < (int)code_count; j++) {
                        if (sym.st_value + base_address == code[j].address) 
                        {
                            strcpy(code[j].function_name, sym_name);    // Map the function name to the disassembled code

                            if(sym.st_size == 0)
                            {
                                code[j].function_size = sym.st_size;    // Handle the case when symbol size is 0
                            }
                            else
                            {
                                code[j].function_size = sym.st_size - 1;    // If size is not 0, subtract 1
                            }
                        }
                    }
                }
            }
        }
    }

    //--------------------------
    // Organize function + offset with bubble sort

    int n = sizeof(function) / sizeof(function[0]); // Calculate the number of elements in the function array

    for (int i = 0; i < n - 1; i++) {   // Sort in ascending order
        for (int j = 0; j < n - i - 1; j++) {
            // Move items with address 0 to the end, and sort based on address
            if (function[j].address == 0 && function[j + 1].address != 0) {
                // Swap using temporary variables
                char temp_name[256];
                unsigned long int temp_address;

                // Swap name
                strcpy(temp_name, function[j].name);
                strcpy(function[j].name, function[j + 1].name);
                strcpy(function[j + 1].name, temp_name);

                // Swap address
                temp_address = function[j].address;
                function[j].address = function[j + 1].address;
                function[j + 1].address = temp_address;
            } else if (function[j].address != 0 && function[j + 1].address != 0) {
                // Compare address values for ascending order
                if (function[j].address > function[j + 1].address) {
                    // Swap using temporary variables
                    char temp_name[256];
                    unsigned long int temp_address;

                    // Swap name
                    strcpy(temp_name, function[j].name);
                    strcpy(function[j].name, function[j + 1].name);
                    strcpy(function[j + 1].name, temp_name);

                    // Swap address
                    temp_address = function[j].address;
                    function[j].address = function[j + 1].address;
                    function[j + 1].address = temp_address;
                }
            }
        }
    }

    char save_function_name[100];

    for(int i = 0; i < (int)code_count; i++)
    {
        if(strcmp("", code[i].function_name))   // If function name is not empty, save it
        {
            strcpy(save_function_name, code[i].function_name);
            code[i].size = 0;   
        }
        else
        {
            strcpy(code[i].function_name, save_function_name);  // If function name is empty, store the saved name 
        }
    }

    code_sum = 0;   // Accumulate for function + offset
    strcpy(save_function_name, "");

    int save_function_size;

    for(int i = 0; i < (int)code_count; i++)
    {
        if(!strcmp(save_function_name, code[i].function_name))  // If it is the same function as the previous one
        {
            if((save_function_size <= code_sum) && (save_function_size != 0))   // If the same function appears multiple times, reset the size to 0
            {
                strcpy(code[i].function_name, "");
                code_sum = 0;   // Reset accumulated size
                code[i].size = 0;  // Reset size to 0
                continue;
            }
            else
            {
                code[i].function_size = save_function_size;  // Update the function size
                code_sum += code[i].size;  // Accumulate the size
                code[i].size = code_sum;  // Update the accumulated size
            }
        }
        else
        {
            code_sum = 0;  // Reset accumulated size
            strcpy(save_function_name, code[i].function_name);  // Save the new function name
            save_function_size = code[i].function_size;  // Save the new function size
        }
    }

    //--------------------------

    // Cleanup
    cs_close(&handle);
    elf_end(elf);
    close(fd);
}

// Function that takes a name and returns the corresponding address
unsigned long int find_func(char name[100])
{
    long int address;
    int i = 0;

    while (strlen(function[i].name) != 0) { // Exit when the name is an empty string
        if(!strcmp(function[i].name, name))
        {
            return function[i].address;
        }
        i++;
    }
}

// Function to print function names and addresses
void print_func() 
{
    int i = 0;
    
    while (strlen(function[i].name) != 0) { // Exit when the name is an empty string
        printf("0x%lx : %s\n", function[i].address, function[i].name);
        i++;
    }
}


// Function to print the contents of the registers
void print_regs(pid_t pid)
{
    // Retrieve the current register values
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    printf("───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── \033[0;35mregisters\033[0m ────\n");

    // Compare each register and output
    printf("%s$rax\033[0m   : 0x%llx\n", 
           (regs.rax != saved_regs.rax) ? "\033[0;92m" : "\033[0;91m", regs.rax);
    printf("%s$rbx\033[0m   : 0x%llx\n", 
           (regs.rbx != saved_regs.rbx) ? "\033[0;92m" : "\033[0;91m", regs.rbx);
    printf("%s$rcx\033[0m   : 0x%llx\n", 
           (regs.rcx != saved_regs.rcx) ? "\033[0;92m" : "\033[0;91m", regs.rcx);
    printf("%s$rdx\033[0m   : 0x%llx\n", 
           (regs.rdx != saved_regs.rdx) ? "\033[0;92m" : "\033[0;91m", regs.rdx);
    printf("%s$rsp\033[0m   : 0x%llx\n", 
           (regs.rsp != saved_regs.rsp) ? "\033[0;92m" : "\033[0;91m", regs.rsp);
    printf("%s$rbp\033[0m   : 0x%llx\n", 
           (regs.rbp != saved_regs.rbp) ? "\033[0;92m" : "\033[0;91m", regs.rbp);
    printf("%s$rsi\033[0m   : 0x%llx\n", 
           (regs.rsi != saved_regs.rsi) ? "\033[0;92m" : "\033[0;91m", regs.rsi);
    printf("%s$rdi\033[0m   : 0x%llx\n", 
           (regs.rdi != saved_regs.rdi) ? "\033[0;92m" : "\033[0;91m", regs.rdi);
    printf("%s$rip\033[0m   : 0x%llx\n", 
           (regs.rip != saved_regs.rip) ? "\033[0;92m" : "\033[0;91m", regs.rip);
    printf("%s$r8 \033[0m   : 0x%llx\n", 
           (regs.r8 != saved_regs.r8) ? "\033[0;92m" : "\033[0;91m", regs.r8);
    printf("%s$r9 \033[0m   : 0x%llx\n", 
           (regs.r9 != saved_regs.r9) ? "\033[0;92m" : "\033[0;91m", regs.r9);
    printf("%s$r10\033[0m   : 0x%llx\n", 
           (regs.r10 != saved_regs.r10) ? "\033[0;92m" : "\033[0;91m", regs.r10);
    printf("%s$r11\033[0m   : 0x%llx\n", 
           (regs.r11 != saved_regs.r11) ? "\033[0;92m" : "\033[0;91m", regs.r11);
    printf("%s$r12\033[0m   : 0x%llx\n", 
           (regs.r12 != saved_regs.r12) ? "\033[0;92m" : "\033[0;91m", regs.r12);
    printf("%s$r13\033[0m   : 0x%llx\n", 
           (regs.r13 != saved_regs.r13) ? "\033[0;92m" : "\033[0;91m", regs.r13);
    printf("%s$r14\033[0m   : 0x%llx\n", 
           (regs.r14 != saved_regs.r14) ? "\033[0;92m" : "\033[0;91m", regs.r14);
    printf("%s$r15\033[0m   : 0x%llx\n", 
           (regs.r15 != saved_regs.r15) ? "\033[0;92m" : "\033[0;91m", regs.r15);

    printf("%s$eflags\033[0m: 0x%llx\n", 
           (regs.eflags != saved_regs.eflags) ? "\033[0;92m" : "\033[0;91m", regs.eflags);

    printf("%s$cs\033[0m : 0x%llx  %s$ss\033[0m : 0x%llx  %s$ds\033[0m : 0x%llx  %s$es\033[0m : 0x%llx  %s$fs\033[0m : 0x%llx  %s$gs\033[0m : 0x%llx\n", 
       (regs.cs != saved_regs.cs) ? "\033[0;92m" : "\033[0;91m", regs.cs,
       (regs.ss != saved_regs.ss) ? "\033[0;92m" : "\033[0;91m", regs.ss,
       (regs.ds != saved_regs.ds) ? "\033[0;92m" : "\033[0;91m", regs.ds,
       (regs.es != saved_regs.es) ? "\033[0;92m" : "\033[0;91m", regs.es,
       (regs.fs != saved_regs.fs) ? "\033[0;92m" : "\033[0;91m", regs.fs,
       (regs.gs != saved_regs.gs) ? "\033[0;92m" : "\033[0;91m", regs.gs);
    
    // Save the current register values
    saved_regs = regs;
}

// Print stack
void print_stack(pid_t pid) 
{
    struct user_regs_struct regs;

    // Get the values of rsp and rbp
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace PTRACE_GETREGS");
        return;
    }
    
    long rsp = regs.rsp;
    long rbp = regs.rbp;

    printf("───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── \033[0;35mstack\033[0m ────\n");

    // Read and print data from the stack in 8-byte increments
    for (int i = 0; i < 10; i++) {
        long stack_value = ptrace(PTRACE_PEEKDATA, pid, rsp + i * 8, NULL);
        if (stack_value == -1) {
            perror("ptrace PEEKDATA");
            break;
        }

        // Print rsp only at the rsp location, and rbp only at the rbp location
        if ((rsp + i * 8 == rbp) && (rsp + i * 8 == rsp)) {
            // Print both rbp and rsp in yellow when they match
            printf("\033[92m%02d\033[0m:%04x│ \033[33mrbp & rsp\033[0m  │ \033[0;94m%p\033[0m ◂— %lx\n", i, i * 8, (void*)(rsp + i * 8), stack_value);
        }
        else if (rsp + i * 8 == rsp) {
            // Print rsp address in yellow
            printf("\033[92m%02d\033[0m:%04x│ \033[33mrsp       \033[0m │ \033[0;94m%p\033[0m ◂— %lx\n", i, i * 8, (void*)(rsp + i * 8), stack_value);
        } else if (rsp + i * 8 == rbp) {
            // Print rbp address in yellow
            printf("\033[92m%02d\033[0m:%04x│ \033[33mrbp       \033[0m │ \033[0;94m%p\033[0m ◂— %lx\n", i, i * 8, (void*)(rsp + i * 8), stack_value);
        } else {
            // Default print for other cases
            printf("\033[92m%02d\033[0m:%04x│            │ \033[0;94m%p\033[0m ◂— %lx\n", i, i * 8, (void*)(rsp + i * 8), stack_value);
        }
    }
}

// Print disassembled code
void print_code()
{
    printf("─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── \033[0;35mcode:x86:64\033[0m ────\n");

    int current_index = -1;

    // Find the current instruction index
    for (int i = 0; i < (int)code_count; i++) {
        if (code[i].address == (regs.rip)) {
            current_index = i;
            break;
        }
    }

    // If current_index is valid, print the instructions
    if (current_index != -1) {
        // Determine the starting and ending indices
        int start_index = current_index - 5;
        int end_index = current_index + 5;

        // Adjust the range if it's out of bounds
        if (start_index < 0) {
            end_index += -start_index; // Extend end_index to make up for the missing range
            start_index = 0;
        }
        if (end_index >= (int)code_count) {
            start_index -= (end_index - (int)code_count + 1); // Extend start_index to make up for the missing range
            end_index = (int)code_count - 1;
        }

        // Ensure start_index is not negative after adjustment
        if (start_index < 0) {
            start_index = 0;
        }

        for (int j = start_index; j <= end_index; j++) {
            if (j == current_index) {
            // Highlight the current instruction in blue
                printf("\033[0;94m → 0x%lx <%s+%04d> : %s %s\033[0m\n", code[j].address, code[j].function_name, code[j].size, code[j].mnemonic, code[j].op_str);
            } 
            else if (j < current_index) 
            {
                // Print instructions before the current instruction in gray
                printf("\033[0;90m   0x%lx <%s+%04d> : %s %s\033[0m\n", code[j].address, code[j].function_name, code[j].size, code[j].mnemonic, code[j].op_str);
            } 
            else {
                // Print other instructions normally
                printf("   0x%lx <%s+%04d> : %s %s\n", code[j].address, code[j].function_name, code[j].size, code[j].mnemonic, code[j].op_str);
            }
        }
    }
    printf("────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────\n");
}

// Disassemble
void disass(char *name) 
{
    if (name[0] == '\0') {  // If the name is empty (the first character is null)
        // Print the entire code
        printf("disassemble \033[1;33mall\033[0m: \n");
        for (int i = 0; i < (int)code_count; i++) {
            printf("    \033[1;32m0x%lx\033[0m <%s+%d>: \033[1;94m%s\033[0m %s\n", 
                    code[i].address, 
                    code[i].function_name, 
                    code[i].size, 
                    code[i].mnemonic, 
                    code[i].op_str);
        }
    } else {
        // Print the code for a specific function name
        printf("disassemble code for function \033[1;33m%s\033[0m: \n", name);
        for (int i = 0; i < (int)code_count; i++) {
            if (strcmp(code[i].function_name, name) == 0) {
                printf("    \033[1;32m0x%lx\033[0m <%s+%d>: \033[1;94m%s\033[0m %s\n", 
                    code[i].address, 
                    code[i].function_name, 
                    code[i].size, 
                    code[i].mnemonic, 
                    code[i].op_str);
            }
        }
    }
}

// Print menu
void menu()
{
    printf("\033[1;31mhelp\033[0m : Print the list of 156dbg commands\n\n");
    printf("\033[1;31mstart\033[0m : Start debugging\n\n");
    printf("\033[1;31mb\033[0m : Set a breakpoint at a specific point\n");
    printf("    \033[1;31mb <address>\033[0m : Set a breakpoint at a specific address\n");
    printf("    \033[1;31mb <function name>\033[0m : Set a breakpoint at the start of a function\n");
    printf("    \033[1;31mb <function name + offset>\033[0m : Set a breakpoint at a function + offset\n\n");
    printf("\033[1;31mc\033[0m : Continue execution\n\n");
    printf("\033[1;31msi\033[0m : Step through execution, enter function calls\n\n");
    printf("\033[1;31mni\033[0m : Step through execution, but do not enter functions\n\n");
    printf("\033[1;31mfunc\033[0m : Print function information\n\n");
    printf("\033[1;31mdisass\033[0m : Disassemble code\n");
    printf("    \033[1;31mdisass\033[0m : Disassemble the entire code\n");
    printf("    \033[1;31mdisass <function name>\033[0m : Disassemble the specific function\n\n");
    printf("\033[1;31mquit\033[0m : Quit the debugger\n\n");

    printf("When you press Enter, the previously executed command will be executed again.\n");
}

// Set breakpoint
void breakpoint(pid_t pid, void* address)
{   
    long int data = ptrace(PTRACE_PEEKTEXT, pid, address, NULL);    // Retrieve the existing data at the location where the breakpoint will be inserted

    if (data == -1 && errno) {
        perror("ptrace PEEKDATA");
        exit(EXIT_FAILURE);
    }

    // POKEDATA: Insert INT3 (0xCC)
    long int int3 = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;

    if (ptrace(PTRACE_POKETEXT, pid, address, int3) == -1) {
        perror("ptrace POKEDATA");
        exit(EXIT_FAILURE);
    }

    printf("Set \033[0;34mbreakpoint%d\033[0m at %p\n", bp_count, address);

    bp[bp_count].save =  data;
    bp[bp_count].address = address;

    bp_count += 1;
}

// Resume execution
void conti(pid_t pid) 
{   
    int status;

    // Resume the process (allow it to hit INT3)
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    
    // Wait for SIGTRAP
    waitpid(pid, &status, 0);

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {

        // Get the current register values
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        // Restore the just-executed instruction
        ptrace(PTRACE_POKETEXT, pid, bp[conti_count].address, bp[conti_count].save);

        // Move RIP to the next instruction (skip the breakpoint instruction)
        regs.rip = (long long)(bp[conti_count].address);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);

        print_regs(pid);
        print_stack(pid);
        print_code();

        conti_count += 1;
    }
}

// Search for RIP
int find_rip(pid_t pid)
{
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    for(int i = 0; i<(int)code_count; i++)
    {
        if(regs.rip == code[i].address)
        {
            return i;   // Return the index of the address pointed to by RIP
        }
    }
}

// Step into
void si(pid_t pid)
{
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
        perror("ptrace(SINGLESTEP) failed");
        return;
    }

    int status;
    waitpid(pid, &status, 0);
        
    print_regs(pid);
    print_stack(pid);
    print_code(pid);
}

// Step over
void ni(pid_t pid) 
{
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    int current_index = find_rip(pid);   

    if(!strcmp(code[current_index].mnemonic, "call"))   // If it's a "call", handle with breakpoint -> continue
    {
        long int data = ptrace(PTRACE_PEEKTEXT, pid, code[current_index + 1].address, NULL); 

        if (data == -1 && errno) {
            perror("ptrace PEEKDATA");
            exit(EXIT_FAILURE);
        }

        // POKEDATA: Insert INT3 (0xCC)
        long int int3 = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;

        if (ptrace(PTRACE_POKETEXT, pid, code[current_index + 1].address, int3) == -1) {
            perror("ptrace POKEDATA");
            exit(EXIT_FAILURE);
        }

        int status;

        ptrace(PTRACE_CONT, pid, NULL, NULL);

        waitpid(pid, &status, 0);

        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        // Restore the just-executed instruction
        ptrace(PTRACE_POKETEXT, pid, code[current_index + 1].address, data);

        // Move RIP to the next instruction (skip the breakpoint instruction)
        regs.rip = (long long)(code[current_index + 1].address);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);

        print_regs(pid);
        print_stack(pid);
        print_code(pid);    
        return;
    }
    else
    {
        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) 
        {
            perror("ptrace(SINGLESTEP) failed");
            return;
        }

        // Wait for the process to stop after executing one instruction
        int status;
        waitpid(pid, &status, 0);

        print_regs(pid);
        print_stack(pid);
        print_code(pid);
    }
}

// Execute debugger
void start(pid_t pid)
{ 
    printf("ep : %p\n", entry_point);
    
    breakpoint(pid, entry_point);   //entry point에 중단점 설정

    conti(pid);
}

// Command processing function
void execute_command(const char *cmd, pid_t pid, char *cmd_history) 
{
    char command[100];  // Command
    char func_name[100];    // Function name argument
    int offset; //<function + offset> for address calculation
    void *address;  // Convert based on offset to address

    // Split the command and its arguments
    sscanf(cmd, "%s", command);

    if (!strcmp(command, "help")) { // Print the manual
        menu();
        strcpy(cmd_history, cmd);
    } else if (!strcmp(command, "start")) { // Start the program
        start(pid);
        strcpy(cmd_history, cmd);
    } else if (!strcmp(command, "b")) { // Set breakpoint
        // Handle "b <address>" or "b <function_name>" format
        if (sscanf(cmd, "b %p", &address) == 1) {
            // Handle "b <address>" format
            breakpoint(pid, address);
            strcpy(cmd_history, cmd);
        } else if (sscanf(cmd, "b %255[^+]+%d", func_name, &offset) == 2) {
            // Handle "b <function_name>+<offset>" format
            address = (void *)find_func(func_name);    // Find the address based on the function name
            if (address) {
                breakpoint(pid, (void *)((char *)address + offset));    // Set breakpoint at address with offset
            } else {
                printf("Error: Function %s not found.\n", func_name);
            }
            strcpy(cmd_history, cmd);
        } 
        else if (sscanf(cmd, "b %s", func_name) == 1) {
            // Handle "b <function_name>" format
            breakpoint(pid, (void*) find_func(func_name));
            strcpy(cmd_history, cmd);
        }
    } else if (!strcmp(command, "c")) { // Resume execution
        conti(pid);
        strcpy(cmd_history, cmd);
    } else if (!strcmp(command, "si")) {    // Execute step by step, enter subroutine (Step Into)
        si(pid);
        strcpy(cmd_history, cmd);
    } else if (!strcmp(command, "ni")) {    // Execute step by step, do not enter subroutine (Step Over)
        ni(pid);
        strcpy(cmd_history, cmd);
    } else if (!strcmp(command, "func")) {  // Print function information
        print_func();
        strcpy(cmd_history, cmd);
    } else if (!strcmp(command, "disass")) {  // Print disassembled code
        // Extract function name from the command
        if (sscanf(cmd, "%*s %s", func_name) == 1) {  // Ignore the first word "disass" and use the second word as the function name
            disass(func_name);  // Print code for the specified function
        } else {
            // If no function name is provided, print everything
            disass("");  // Print everything
        }
        strcpy(cmd_history, cmd);  // Save command history
    } else if (!strcmp(command, "quit")) {  // Exit
        ptrace(PTRACE_KILL, pid, NULL, NULL);   // Exit debugging by terminating the child process
        exit(1);
    } else {
        printf("Invalid command: %s. Try help\n", command);
    }
}

// Debugger loop function
void debugger(pid_t pid) 
{
    printf("\033[1;34m156 debugger\033[0m(\033[1;33mver 1.0\033[0m) running\n");

    char cmd[100] = {0};    // Command
    char cmd_history[100] = {0};    // Command history

    while (1) {
        printf("\033[0;94m156dbg➤\033[0m ");
        fgets(cmd, sizeof(cmd), stdin); // Get input from the user
        cmd[strcspn(cmd, "\n")] = '\0'; // Remove newline character

        if (strlen(cmd) == 0) {
            // If no input, repeat the previous command
            if (strlen(cmd_history) > 0) {
                printf("(Repeating command: \033[1;33m%s\033[0m)\n", cmd_history);
                execute_command(cmd_history, pid, cmd_history);
            } else {
                printf("No previous command to repeat.\n");
            }
        } else {
            // Execute the new command
            execute_command(cmd, pid, cmd_history);
        }
    }
    waitpid(pid, 0, 0);  // Wait for the child process to finish
}

// Main function
int main(int argc, char *argv[]) 
{
    if (argc != 2) {
        printf("<usage> : 156dbg [file]\n");
        exit(1);
    } else {
        pid_t pid = fork(); // Create a child process using fork()

        if (pid == 0) {
            ptrace(PTRACE_TRACEME, 0, NULL, NULL);  // Make the child process traceable by the debugger
            execl(argv[1], argv[1], NULL);  // Execute the given program
        } else {
            printf("File \033[1;34m%s\033[0m runs as a debug process (pid : \033[1;35m%d\033[0m)\n", argv[1], pid);
            sleep(2);   // Wait for 2 seconds to ensure the process ID has changed properly
            ptrace(PTRACE_ATTACH, pid, NULL, NULL); // Attach to the debug process to gain control
            elf_parsing(pid, argv[1]);  // Parse necessary data from the ELF file
            debugger(pid);  // Start the debugger mode
        }
    }
}
