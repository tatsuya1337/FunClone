#pragma once

#include <zydis_wrapper.hpp>
#include <cstddef>
#include <iostream>
#include <map>
#include <unordered_map>
#include <set>
#include <queue>

namespace vapor {

    class funclone {
    public:

        funclone(void* address, void* buffer = nullptr, size_t size = 0)
            : address_(address), buffer_(buffer), original_size_(size)
        {
            init();
        }

        funclone(const zydis::InstructionCondition& end_condition_fn, void* address, void* buffer = nullptr, size_t extra_buffer_size = 0)
            : end_condition_fn_(end_condition_fn), address_(address), buffer_(buffer), extra_buffer_size_(extra_buffer_size)
        {
            init();
        }

        ~funclone();

        // Gets buffer_ address
        uintptr_t address() const noexcept;

        // Gets the first instruction
        zydis::single_instruction first_instruction() const;

        // Gets the last instruction
        zydis::single_instruction last_instruction() const;

        // Searches for the instruction that meets with the conditions of the given search function
        zydis::single_instruction find(const zydis::InstructionCondition& condition) const noexcept;

        // Gets the original function size
        size_t original_size() const;

        // Gets the cloned function size
        size_t cloned_size() const;

        template <typename Ret, typename... Args>
        __forceinline Ret call(Args... args)
        {
            using FuncType = Ret(*)(Args...);

            FuncType func = reinterpret_cast<FuncType>(first_instruction().address());

            return func(args...);
        }

    private:
        void init();

        zydis::InstructionCondition end_condition_fn_{}; // Checks conditions to stop iteration

        void* address_{};   // Original function address
        void* buffer_{};     // Cloned function buffer address
        size_t extra_buffer_size_{}; // Extra size added to the end of the cloned function
        size_t original_size_{};      // Size of the original function
        size_t clone_size_{};   // Size of the cloned function
        void* spoof_address_{}; // Dynamically obtained address for return address spoofing
        bool buffer_owned_{}; // Indicates whether buffer is manually allocated or not
        zydis::single_instruction last_instruction_{}; // The instruction after the one found by end_condition_fn_

        std::vector<zydis::single_instruction> rip_relative_call_instructions_{};
        std::vector<zydis::single_instruction> rip_relative_instructions_{};
        std::vector<zydis::single_instruction> unconditional_jumps_{};
        std::vector<zydis::single_instruction> conditional_jumps_{};
        std::vector<zydis::single_instruction> relative_calls_{};

        std::map<uintptr_t, uintptr_t> address_mapping_{};
        std::unordered_map<uintptr_t, std::vector<uint8_t>> relocated_bytes_{};

        // Searches for jmp rdi in .text section of the current process and sets its address to spoof_address_ 
        void search_spoof_address();

        // Loops through every instruction in the original function and fill class member vectors
        void analyze_instructions();

        // Converts all rip relative instructions to absolute ones, including rip relative calls, e.g.) call [0x7FF73EBB7490]
        void relocate_rip_relative();

        // Widens the instruction to fit the new jump target
        void translate_unconditional_jumps();

        // Writes unconditional jump targets to buffer_
        void relocate_unconditional_jumps();

        // Widens the instruction to fit the new jump target
        void translate_conditional_jumps();

        // Writes conditional jump targets to buffer_
        void relocate_conditional_jumps();

        // Converts all relative call instructions into absolute ones and wraps it around with a return address spoofer
        void relocate_calls();

        // Inserts the original and newly generated instructions to buffer_
        void copy();

        // Gets the final size of the cloned function
        size_t finalized_size();

        // Calculates the function size
        size_t calc_size();

        /*
        * With the found fake return address as spoof_address_ and tls_storage variable, generates an absolute call instruction with thread safe return address spoofer
        * A detailed explanation is below
        *
        * 1. Saves RCX through R9 registers onto the stack, calls `get_tls_storage()`, and restores the registers.
        * 2. Saves the original RDI value into thread-local storage.
        * 3. Saves the original return address into RDI.
        * 4. Pushes `spoof_address_` (a `jmp rdi` instruction) onto the stack as the return address.
        * 5. Jumps to the target function; its return address is now `spoof_address_`.
        * 6. Upon return, `spoof_address_` executes `jmp rdi`, transferring control to the saved address in RDI.
        * 7. Pushes RAX to save the target function's return value.
        * 8. Retrieves and restores the original RDI from thread-local storage.
        * 9. Pops RAX to restore the return value.
        */
        zydis::encoder::encoded_instructions build_call_spoofer(uintptr_t target);
        
        // Gets .text section info, the start adddress and its size
        std::pair<const uint8_t*, size_t> text_section_info();
    };

}