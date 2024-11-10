#include "funclone.hpp"

namespace vapor {

	static thread_local void* tls_storage = nullptr;

	static void** get_tls_storage()
	{
		return &tls_storage;
	}

	funclone::~funclone()
	{
		if (buffer_owned_ && buffer_) {
			VirtualFree(buffer_, 0, MEM_RELEASE);
			buffer_ = nullptr;
		}
	}

	void funclone::init()
	{
		if (!original_size_)
			original_size_ = calc_size();

		analyze_instructions();

		search_spoof_address();

		relocate_calls();
		relocate_rip_relative();

		translate_unconditional_jumps();
		translate_conditional_jumps();

		if (!buffer_)
		{
			buffer_ = VirtualAlloc(nullptr, finalized_size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			buffer_owned_ = true;
		}

		copy();

		relocate_conditional_jumps();
		relocate_unconditional_jumps();
	}

	void funclone::search_spoof_address()
	{
		auto search = [&](const std::vector<uint8_t>& pattern, const std::string& mask, const uint8_t* startAddress, size_t size) -> uintptr_t {
			auto match = [&](const uint8_t* data) -> bool {
				for (size_t i = 0; i < pattern.size(); ++i) {
					if (mask[i] == 'x' && data[i] != pattern[i]) {
						return false;
					}
				}
				return true;
				};

			for (size_t i = 0; i <= size - pattern.size(); ++i) {
				const uint8_t* currentAddress = startAddress + i;
				if (match(currentAddress)) {
					return reinterpret_cast<uintptr_t>(currentAddress);
				}
			}

			return 0;
			};

		static auto [textBase, textSize] = text_section_info();

		std::vector<uint8_t> pattern = { 0xFF, 0xE7 };
		std::string mask = "xx";

		spoof_address_ = (void*)search(pattern, mask, textBase, textSize);
	}

	void funclone::analyze_instructions()
	{
		uintptr_t start_address = reinterpret_cast<uintptr_t>(address_);
		uintptr_t end_address = start_address + original_size_;

		for (auto& instruction : zydis::instructions(start_address))
		{
			if (instruction.address() >= end_address)
				break;

			for (uint8_t i = 0; i < instruction.info().operand_count_visible; ++i) {
				ZydisDecodedOperand op = instruction.operand(i);

				if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base == ZYDIS_REGISTER_RIP)
				{
					if (instruction.info().mnemonic == ZYDIS_MNEMONIC_CALL)
					{
						rip_relative_call_instructions_.push_back(instruction);
						break;
					}

					rip_relative_instructions_.push_back(instruction);
					break;
				}

				if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative)
				{
					if (instruction.info().mnemonic == ZYDIS_MNEMONIC_CALL)
						relative_calls_.push_back(instruction);
					else if (instruction.info().meta.category == ZYDIS_CATEGORY_UNCOND_BR)
						unconditional_jumps_.push_back(instruction);
					else if (instruction.info().meta.category == ZYDIS_CATEGORY_COND_BR)
						conditional_jumps_.push_back(instruction);

					break;
				}
			}

			if (end_condition_fn_ && end_condition_fn_(instruction))
			{
				last_instruction_ = instruction.next();
				break;
			}
		}
	}

	void funclone::relocate_rip_relative()
	{
		for (const auto& instruction : rip_relative_call_instructions_)
			relocated_bytes_[instruction.address()] = build_call_spoofer(*(uintptr_t*)instruction.relative_to_absolute()).bytes();

		for (const auto& instruction : rip_relative_instructions_)
		{
			auto target_register = ZYDIS_REGISTER_RBX;

			for (uint8_t i = 0; i < instruction.info().operand_count; ++i)
			{
				if (instruction.operand(i).type == ZYDIS_OPERAND_TYPE_REGISTER)
				{
					switch (instruction.operand(i).reg.value)
					{

					case ZYDIS_REGISTER_RBX:
					case ZYDIS_REGISTER_EBX:
					case ZYDIS_REGISTER_BX:
					case ZYDIS_REGISTER_BL:
						target_register = ZYDIS_REGISTER_R12;
						break;

					default:
						break;
					}
				}
			}

			ZydisEncoderRequest request = instruction.encoder_struct();

			std::vector<zydis::encoder::operand> new_operands{};
			for (uint8_t i = 0; i < request.operand_count; ++i) {
				const ZydisEncoderOperand& op = request.operands[i];
				switch (op.type) {
				case ZYDIS_OPERAND_TYPE_REGISTER:
					new_operands.push_back(zydis::encoder::register_operand(op.reg.value));
					break;
				case ZYDIS_OPERAND_TYPE_IMMEDIATE:
					new_operands.push_back(zydis::encoder::immediate_operand(op.imm.u));
					break;
				case ZYDIS_OPERAND_TYPE_MEMORY:
					new_operands.push_back(zydis::encoder::memory_operand(target_register, op.mem.index, op.mem.scale, 0, op.mem.size));
					break;
				default:
					break;
				}
			}

			auto encoded = zydis::encoder::encode
			(
				{

				{ ZYDIS_MNEMONIC_PUSH, { zydis::encoder::register_operand(target_register) } },
				{ ZYDIS_MNEMONIC_MOV, { zydis::encoder::register_operand(target_register), zydis::encoder::immediate_operand(instruction.relative_to_absolute()) } },
				{ request.mnemonic, { new_operands  } },
				{ ZYDIS_MNEMONIC_POP, { zydis::encoder::register_operand(target_register) } }

				}
			);

			relocated_bytes_[instruction.address()] = encoded.bytes();
		}
	}

	void funclone::translate_unconditional_jumps()
	{
		for (const auto& instruction : unconditional_jumps_)
			relocated_bytes_[instruction.address()] = zydis::encoder::encode_absolute_jump(0x0).bytes();
	}

	void funclone::relocate_unconditional_jumps()
	{
		uintptr_t start_address = reinterpret_cast<uintptr_t>(address_);
		uintptr_t end_address = start_address + original_size_;

		for (const auto& instruction : unconditional_jumps_)
		{
			// Calculate the absolute address of the original jump target
			uintptr_t original_target = instruction.relative_to_absolute();
			uintptr_t new_target = original_target;
			uintptr_t new_address = address_mapping_[instruction.address()];

			// Check if the jump target is within the original function bounds
			if (original_target >= start_address && original_target < end_address)
				new_target = address_mapping_[original_target];

			zydis::encoder::encode_absolute_jump(new_target).write_to_raw(reinterpret_cast<void*>(new_address));
		}
	}

	void funclone::translate_conditional_jumps()
	{
		for (const auto& instruction : conditional_jumps_)
		{
			ZydisEncoderRequest request = instruction.encoder_struct();

			request.branch_type = ZYDIS_BRANCH_TYPE_NEAR;
			request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;

			relocated_bytes_[instruction.address()] = zydis::encoder::encode(request).bytes();
		}
	}

	void funclone::relocate_conditional_jumps()
	{
		uintptr_t start_address = reinterpret_cast<uintptr_t>(address_);
		uintptr_t end_address = start_address + original_size_;

		for (const auto& instruction : conditional_jumps_)
		{
			uintptr_t original_target = instruction.relative_to_absolute();

			if (original_target >= start_address && original_target < end_address) {
				uintptr_t new_target = address_mapping_[original_target];
				uintptr_t new_address = address_mapping_[instruction.address()];

				auto request_instruction = zydis::single_instruction(new_address);

				ZydisEncoderRequest request = request_instruction.encoder_struct();

				for (uint8_t i = 0; i < request.operand_count; ++i) {
					if (request.operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
						ZyanI64 new_disp = static_cast<ZyanI64>(new_target - address_mapping_[instruction.address()] - request_instruction.info().length);
						request.operands[i].imm.s = new_disp;
					}
				}

				zydis::encoder::encode(request).write_to_raw(reinterpret_cast<void*>(new_address));
			}

		}
	}

	void funclone::relocate_calls()
	{
		for (const auto& instruction : relative_calls_)
			relocated_bytes_[instruction.address()] = build_call_spoofer(instruction.relative_to_absolute()).bytes();
	}

	zydis::encoder::encoded_instructions funclone::build_call_spoofer(uintptr_t target)
	{
		auto get_tls_storage_encoded = zydis::encoder::encode
		(
			{

			{ ZYDIS_MNEMONIC_PUSH, { zydis::encoder::register_operand(ZYDIS_REGISTER_RCX)} },
			{ ZYDIS_MNEMONIC_PUSH, { zydis::encoder::register_operand(ZYDIS_REGISTER_RDX)} },
			{ ZYDIS_MNEMONIC_PUSH, { zydis::encoder::register_operand(ZYDIS_REGISTER_R8)} },
			{ ZYDIS_MNEMONIC_PUSH, { zydis::encoder::register_operand(ZYDIS_REGISTER_R9)} },
			}
			);

		get_tls_storage_encoded += zydis::encoder::encode_absolute_call((uintptr_t)get_tls_storage);

		get_tls_storage_encoded += zydis::encoder::encode
		(
			{

			{ ZYDIS_MNEMONIC_POP, { zydis::encoder::register_operand(ZYDIS_REGISTER_R9)} },
			{ ZYDIS_MNEMONIC_POP, { zydis::encoder::register_operand(ZYDIS_REGISTER_R8)} },
			{ ZYDIS_MNEMONIC_POP, { zydis::encoder::register_operand(ZYDIS_REGISTER_RDX)} },
			{ ZYDIS_MNEMONIC_POP, { zydis::encoder::register_operand(ZYDIS_REGISTER_RCX)} },

			}
			);

		auto encoded = get_tls_storage_encoded + zydis::encoder::encode
		(
			{

			{ ZYDIS_MNEMONIC_MOV, { zydis::encoder::memory_operand(ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_NONE, 0, 0x0, sizeof(uint64_t)), zydis::encoder::register_operand(ZYDIS_REGISTER_RDI)} },
			{ ZYDIS_MNEMONIC_LEA, { zydis::encoder::register_operand(ZYDIS_REGISTER_RDI),  zydis::encoder::memory_operand(ZYDIS_REGISTER_RIP, ZYDIS_REGISTER_NONE, 0, 0x19, sizeof(uint64_t))} },
			{ ZYDIS_MNEMONIC_MOV, { zydis::encoder::register_operand(ZYDIS_REGISTER_RAX), zydis::encoder::immediate_operand(spoof_address_)} },
			{ ZYDIS_MNEMONIC_PUSH, { zydis::encoder::register_operand(ZYDIS_REGISTER_RAX)} },

			}
			);

		encoded += zydis::encoder::encode_absolute_jump((uintptr_t)target);
		encoded += zydis::encoder::encode({ { ZYDIS_MNEMONIC_PUSH, { zydis::encoder::register_operand(ZYDIS_REGISTER_RAX)} } });

		encoded += get_tls_storage_encoded;

		encoded += zydis::encoder::encode
		(
			{

			{ ZYDIS_MNEMONIC_MOV, { zydis::encoder::register_operand(ZYDIS_REGISTER_RDI), zydis::encoder::memory_operand(ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_NONE, 0, 0x0, sizeof(uint64_t))} },
			{ ZYDIS_MNEMONIC_POP, { zydis::encoder::register_operand(ZYDIS_REGISTER_RAX)} },

			}
			);

		return encoded;
	}

	size_t funclone::finalized_size()
	{
		uintptr_t start_address = reinterpret_cast<uintptr_t>(address_);
		uintptr_t end_address = start_address + original_size_;

		size_t offset = extra_buffer_size_;

		for (auto& instruction : zydis::instructions(start_address)) {
			if (instruction.address() >= end_address)
				break;

			if (instruction.address() == last_instruction_.address())
			{
				auto jmp_instruction = zydis::encoder::encode_absolute_jump((uintptr_t)last_instruction_.address());
				offset += jmp_instruction.size();
				break;
			}

			auto& bytes = relocated_bytes_[instruction.address()];

			if (!bytes.empty())
			{
				offset += bytes.size();
				continue;
			}

			offset += instruction.info().length;
		}

		return offset;
	}

	void funclone::copy()
	{
		uintptr_t start_address = reinterpret_cast<uintptr_t>(address_);
		uintptr_t end_address = start_address + original_size_;

		uint32_t offset = 0;

		for (auto& instruction : zydis::instructions(start_address)) {

			if (instruction.address() >= end_address)
				break;

			uintptr_t new_address = reinterpret_cast<uintptr_t>(buffer_) + offset;
			address_mapping_[instruction.address()] = new_address;

			if (instruction.next().address() >= end_address)
				last_instruction_ = zydis::single_instruction(new_address);

			if (instruction.address() == last_instruction_.address())
			{
				auto jmp_instruction = zydis::encoder::encode_absolute_jump((uintptr_t)last_instruction_.address());

				jmp_instruction.write_to_raw((void*)new_address);
				offset += jmp_instruction.size();

				last_instruction_ = zydis::single_instruction(new_address);
				break;
			}

			auto& bytes = relocated_bytes_[instruction.address()];

			// Modified instruction
			if (!bytes.empty())
			{
				std::memcpy((void*)new_address, bytes.data(), bytes.size());
				offset += bytes.size();

				continue;
			}

			// Original instruction
			instruction.write_to_raw(reinterpret_cast<void*>(new_address));
			offset += instruction.info().length;
		}

		offset += extra_buffer_size_;

		clone_size_ = offset;
	}

	uintptr_t funclone::address() const noexcept {
		return (uintptr_t)buffer_;
	}

	zydis::single_instruction funclone::first_instruction() const {
		return zydis::single_instruction(buffer_);
	}

	zydis::single_instruction funclone::last_instruction() const {
		return zydis::single_instruction(last_instruction_);
	}

	zydis::single_instruction funclone::find(const zydis::InstructionCondition& condition) const noexcept {
		return first_instruction().find(condition);
	}

	size_t funclone::original_size() const {
		return original_size_;
	}
	size_t funclone::cloned_size() const {
		return clone_size_;
	}

	size_t funclone::calc_size() {
		// Custom maximum function to avoid Windows.h conflicts
		static auto max_s = [](auto a, auto b) { return (a > b) ? a : b; };

		size_t function_size = 0;

		std::set<uintptr_t> visited_offsets{};
		std::queue<uintptr_t> work_queue{};
		auto start_address = reinterpret_cast<uintptr_t>(address_);

		work_queue.push(start_address);

		while (!work_queue.empty()) {
			// Get the current address to process
			uintptr_t current_address = work_queue.front();
			work_queue.pop();

			// Skip if already visited
			if (visited_offsets.find(current_address) != visited_offsets.end()) {
				continue;
			}

			// Mark this address as visited
			visited_offsets.insert(current_address);

			// Iterate over instructions starting from the current address
			for (auto& instruction : zydis::instructions(current_address))
			{
				function_size = max_s(function_size, instruction.address() - start_address + instruction.info().length);

				// Handle conditional and unconditional branches, e.g.) je, jne, ja, jmp instructions
				if ((instruction.info().meta.category == ZYDIS_CATEGORY_COND_BR || instruction.info().meta.category == ZYDIS_CATEGORY_UNCOND_BR) &&
					instruction.operand(0).type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {

					auto jump_target = zydis::single_instruction(instruction.relative_to_absolute());

					if (jump_target.is_valid() && visited_offsets.find(jump_target.address()) == visited_offsets.end())
					{
						auto is_prologue = [&]() -> bool
							{
								for (auto& instruction : zydis::instructions(jump_target.address()))
								{
									if (instruction.iteration_count() >= 10)
										break;

									if (instruction.info().mnemonic == ZYDIS_MNEMONIC_PUSH)
										return true;

								}
								return false;
							};

						// This will break if it jumps to a new function but it doesn't push stack, I have no idea how to handle such case, if anyone has a better idea please let me know.
						if (!is_prologue())
							work_queue.push(jump_target.address());
					}
				}

				// Handle indirect branches, RET, and tail calls, e.g.) ret, jmp immediate(E9 ? ? ? ?), jmp [register], jmp [memory] instructions
				if (instruction.info().mnemonic == ZYDIS_MNEMONIC_RET ||
					(instruction.info().mnemonic == ZYDIS_MNEMONIC_JMP && instruction.operand(0).type == ZYDIS_OPERAND_TYPE_IMMEDIATE) ||
					(instruction.info().meta.category == ZYDIS_CATEGORY_UNCOND_BR && instruction.operand(0).type == ZYDIS_OPERAND_TYPE_MEMORY)) {
					break; // End the current block or stop processing
				}
			}

		}

		return function_size;
	}

	std::pair<const uint8_t*, size_t> funclone::text_section_info()
	{
		auto baseAddress = *(uintptr_t*)(__readgsqword(0x60) + 0x10);

		auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(baseAddress);
		auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(baseAddress + dosHeader->e_lfanew);

		constexpr uint64_t TEXT_SECTION_NAME = 0x747865742E;  // ".text" in little-endian

		auto* section = IMAGE_FIRST_SECTION(ntHeaders);
		for (uint16_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {

			if (*reinterpret_cast<const uint64_t*>(section->Name) == TEXT_SECTION_NAME) {
				const uint8_t* textBase = reinterpret_cast<const uint8_t*>(
					baseAddress + section->VirtualAddress);
				size_t textSize = section->Misc.VirtualSize;
				return { textBase, textSize };
			}
		}

		return { nullptr, 0 };
	}
}
