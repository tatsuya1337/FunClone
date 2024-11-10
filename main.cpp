#include <zydis_wrapper.hpp>
#include <funclone/funclone.hpp>
#include <iostream>

auto local_player = new uintptr_t;

#pragma optimize( "", off )
void* get_local_controller(uintptr_t obj)
{
	return (void*)(obj + 0x20);
}

void* get_local_controller_pawn()
{
	auto controller = get_local_controller((uintptr_t)local_player);

	if (!controller)
		return nullptr;

	return (void*)((uintptr_t)controller + 0x30);
}
#pragma optimize( "", on )

int main()
{
	// Lambda function to check whether the instruction is call or not
	auto filter_func = FIND_SIGNATURE_LAMBDA
	{
		if (instruction.info().mnemonic == ZYDIS_MNEMONIC_CALL)
			return true;

	return false;
	};

	// Makes a new funclone object of get_local_controller_pawn.
	// filter_func is a zydis::InstructionCondition function to tell the class when to stop cloning. (Optional)
	// If zydis::InstructionCondition is provided, funclone will insert an absolute jump at the end to the next instruction of the found instruction.
	auto cloned_func_1 = vapor::funclone(filter_func, get_local_controller_pawn);

	// Gets the epilogue region in the original function. The cloned function does not contain it because of the given filter_func above.
	auto cloned_func_1_epilogue = zydis::single_instruction(get_local_controller_pawn).find(zydis::find_predicates::is_epilogue);

	// Encodes absolute jump instruction, to the found epilogue.
	auto encoded_jump_to_epilogue = zydis::encoder::encode_absolute_jump(cloned_func_1_epilogue.address());

	// Rewrites the last instruction of the cloned function.
	// In this example, It is an absolute jump to the instruction right after call.
	// Because zydis::InstructionCondition is provided to the funclone constructor.
	cloned_func_1.last_instruction().rewrite(encoded_jump_to_epilogue.bytes());

	// Now cloned_func_1 returns immediately after get_local_controller() gets called.
	auto cloned_result = cloned_func_1.call<void*>();

	std::cout << std::hex << "cloned_result: " << cloned_result << std::endl;
	std::cout << std::hex << "orig_result: " << get_local_controller_pawn() << std::endl;

	getchar();

	return 0;
}
