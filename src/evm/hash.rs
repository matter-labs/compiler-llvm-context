//!
//! Translates the hash instruction.
//!

use inkwell::types::BasicType;
use inkwell::values::BasicValue;

use crate::context::address_space::AddressSpace;
use crate::context::Context;
use crate::Dependency;

///
/// Translates the hash instruction.
///
pub fn keccak256<'ctx, D>(
    context: &mut Context<'ctx, D>,
    input_offset: inkwell::values::IntValue<'ctx>,
    input_size: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let input_size_shifted = context.builder().build_left_shift(
        input_size,
        context.field_const(compiler_common::BITLENGTH_X64 as u64),
        "keccak256_call_input_size_shifted",
    );
    let abi_data = context.builder().build_int_add(
        input_size_shifted,
        input_offset,
        "keccak256_call_abi_data",
    );

    let address = context.field_const_str(compiler_common::ABI_ADDRESS_KECCAK256);

    let result_type = context
        .structure_type(vec![
            context
                .integer_type(compiler_common::BITLENGTH_FIELD)
                .as_basic_type_enum(),
            context
                .integer_type(compiler_common::BITLENGTH_BOOLEAN)
                .as_basic_type_enum(),
        ])
        .as_basic_type_enum();
    let result_pointer = context.build_alloca(result_type, "keccak256_call_result_pointer");

    let result_pointer = context
        .build_call(
            context.runtime.static_call,
            &[
                address.as_basic_value_enum(),
                abi_data.as_basic_value_enum(),
                result_pointer.as_basic_value_enum(),
            ],
            "keccak256_call_external",
        )
        .expect("Always returns a value");
    let result_abi_data_pointer = context
        .builder()
        .build_struct_gep(
            result_pointer.into_pointer_value(),
            0,
            "keccak256_call_external_result_abi_data_pointer",
        )
        .expect("Always valid");
    let result_abi_data = context.build_load(
        result_abi_data_pointer,
        "keccak256_call_external_result_abi_data",
    );

    let child_offset = context.builder().build_and(
        result_abi_data.into_int_value(),
        context.field_const(compiler_common::BITLENGTH_X64 as u64),
        "keccak256_child_offset",
    );
    let child_pointer =
        context.access_memory(child_offset, AddressSpace::Child, "keccak256_child_pointer");

    let result = context.build_load(child_pointer, "keccak256_result");

    Ok(Some(result))
}
