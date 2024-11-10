# FunClone

**FunClone** is a modern C++ library that lets you clone and modify x64 functions dynamically. It builds upon [Zydis](https://github.com/zyantific/zydis) for disassembly and is based on my own [zydis_wrapper](https://github.com/tatsuya1337/zydis_wrapper). With **FunClone**, you can manipulate functions at runtime without worrying about CRC or disrupting the program's control flow.

# Use Cases

- **Decrypting Encrypted Pointers or Values**: In scenarios where pointers or values are encrypted for security reasons, **FunClone** allows you to clone and modify the decryption functions to retrieve the decrypted data without altering the original function. Useful when the function doesn't return the decrypted data but it decrypts at some point.

- **Dynamic Function Modification**: Modify cloned functions at runtime without affecting the integrity of the original process, which is crucial for applications that have integrity checks or are sensitive to modifications.

- **Function Control and Analysis**: Gain full control over function execution by cloning and modifying functions, useful for debugging, testing, or bypassing certain checks without disrupting the main control flow or triggering anti-tampering mechanisms.

# Example

In this example, **FunClone** clones a dummy function `void* get_local_controller_pawn()` and modifies it to return when get_local_controller() aka the first call instruction is executed.\
So it essentially becomes `void* get_local_controller()` from `void* get_local_controller_pawn()`.

```cpp
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
```

#### Result
```
cloned_result: 0000011F7E1A2100
orig_result: 0000011F7E1A2130
```

# Usage

Before using **FunClone**, ensure your project includes the following:

- **C++ Compiler**: C++20 or higher (e.g., Visual Studio 2022 if using the provided `.sln` file)
- **Libraries**:
  - [Zydis Library](https://github.com/zyantific/zydis)
  - [My Zydis Wrapper](https://github.com/tatsuya1337/zydis_wrapper)
- **Source Files**:
  - [funclone.hpp](./include/funclone/funclone.hpp)
  - [funclone.cpp](./include/funclone/funclone.cpp)

### Constructing a FunClone Object

You can construct a `funclone` object using either an integer address or a function pointer. **FunClone** provides two constructors:

1. **Basic Constructor**

   ```cpp
   funclone(void* address, void* buffer = nullptr, size_t size = 0);
   ```

   - **address**: The address of the function to clone.
   - **buffer** *(optional)*: A memory buffer where the cloned function will be stored. If `nullptr`, a buffer is allocated dynamically by `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` protection.
   - **size** *(optional)*: The size of the orginal function. If `0`, the function size is calculated dynamically.

2. **Constructor with End Condition**

   ```cpp
   funclone(const zydis::InstructionCondition& end_condition_fn, void* address, void* buffer = nullptr, size_t extra_buffer_size = 0);
   ```

   - **end_condition_fn**: A predicate function that determines when to stop cloning.
   - **address**, **buffer**: Same as above.
   - **extra_buffer_size_** *(optional)*: Additional size (in bytes) to be added to the cloned function's buffer. Useful when you want to insert extra instructions at the end.

### Examples

#### Example 1: Cloning a Function with Automatic Size Calculation

```cpp
// Clones the function at address 0x7FF797516C80.
// FunClone will dynamically calculate the function size and allocate a buffer for the cloned function.
funclone cloned_func((void*)0x7FF797516C80);
```

#### Example 2: Cloning a Function to a Specific Buffer with Fixed Size

```cpp
// Clones the function at address 0x7FF797516C80 into a buffer at address 0x27A017C0000 with a fixed size of 0x1024 bytes.
funclone cloned_func((void*)0x7FF797516C80, (void*)0x27A017C0000, 0x1024);
```

#### Example 3: Cloning a Function Until a Specific Instruction

```cpp
// Convenient macro for creating a lambda function with ease
// Defined in zydis_wrapper/helper/types.hpp
#define FIND_SIGNATURE_LAMBDA [&](const zydis::single_instruction& instruction) -> bool

// Use the macro to define the end condition lambda function
auto filter_func = FIND_SIGNATURE_LAMBDA
{
    // Stop cloning after the third instruction (iteration_count starts from 0).
    return instruction.iteration_count() == 3;
};

// Clones the function at address 0x7FF797516C80 until it reaches the fourth instruction.
// FunClone will insert an absolute jump at the end to the next instruction (the fifth instruction).
funclone cloned_func(filter_func, (void*)0x7FF797516C80);
```