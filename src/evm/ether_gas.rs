//!
//! Translates the value and balance operations.
//!

use inkwell::types::BasicType;
use inkwell::values::BasicValue;

use crate::context::address_space::AddressSpace;
use crate::context::function::intrinsic::Intrinsic as IntrinsicFunction;
use crate::context::Context;
use crate::Dependency;

///
/// Translates the `gas` instruction.
///
pub fn gas<'ctx, D>(
    context: &mut Context<'ctx, D>,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    Ok(context.build_call(
        context.get_intrinsic_function(IntrinsicFunction::ErgsLeft),
        &[],
        "ergs_left",
    ))
}

///
/// Translates the `value` instruction.
///
pub fn value<'ctx, D>(
    context: &mut Context<'ctx, D>,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    Ok(context.build_call(
        context.get_intrinsic_function(IntrinsicFunction::GetU128),
        &[],
        "get_u128_value",
    ))
}

///
/// Translates the `balance` instruction.
///
pub fn balance<'ctx, D>(
    context: &mut Context<'ctx, D>,
    address: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let balance_call_success_block = context.append_basic_block("balance_call_success_block");
    let balance_call_join_block = context.append_basic_block("balance_call_join_block");

    let input_offset = context.field_const(
        (compiler_common::ABI_MEMORY_OFFSET_ARBITRARY_EXTERNAL_CALL_SPACE
            * compiler_common::SIZE_FIELD) as u64,
    );
    let input_length_shifted = context.builder().build_left_shift(
        context.field_const((compiler_common::SIZE_X32 + compiler_common::SIZE_FIELD) as u64),
        context.field_const(compiler_common::BITLENGTH_X64 as u64),
        "balance_call_input_length_shifted",
    );
    let abi_data = context.builder().build_int_add(
        input_length_shifted,
        input_offset,
        "balance_call_abi_data",
    );

    let signature_hash = crate::hashes::keccak256("balanceOf(address)".as_bytes());
    let signature_pointer = context.access_memory(
        input_offset,
        AddressSpace::Heap,
        "balance_call_signature_pointer",
    );
    let signature_value = context.field_const_str(signature_hash.as_str());
    context.build_store(signature_pointer, signature_value);

    let address_offset = context.builder().build_int_add(
        input_offset,
        context.field_const(compiler_common::SIZE_X32 as u64),
        "balance_call_address_offset",
    );
    let address_pointer = context.access_memory(
        address_offset,
        AddressSpace::Heap,
        "balance_call_address_pointer",
    );
    context.build_store(address_pointer, address);

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
    let result_pointer = context.build_alloca(result_type, "balance_call_result_pointer");

    let result_pointer = context
        .build_invoke(
            context.runtime.static_call,
            &[
                context
                    .field_const_str(compiler_common::ABI_ADDRESS_ETH_TOKEN)
                    .as_basic_value_enum(),
                abi_data.as_basic_value_enum(),
                result_pointer.as_basic_value_enum(),
            ],
            "balance_call",
        )
        .expect("Always returns a value");

    let result_abi_data_pointer = unsafe {
        context.builder().build_gep(
            result_pointer.into_pointer_value(),
            &[
                context.field_const(0),
                context
                    .integer_type(compiler_common::BITLENGTH_X32)
                    .const_zero(),
            ],
            "balance_call_result_abi_data_pointer",
        )
    };
    let result_abi_data =
        context.build_load(result_abi_data_pointer, "balance_call_result_abi_data");
    let child_data_offset = context.builder().build_and(
        result_abi_data.into_int_value(),
        context.field_const(u64::MAX as u64),
        "balance_call_child_data_offset",
    );
    let child_data_length_shifted = context.builder().build_right_shift(
        result_abi_data.into_int_value(),
        context.field_const(compiler_common::BITLENGTH_X64 as u64),
        false,
        "balance_call_child_data_length_shifted",
    );
    let child_data_length = context.builder().build_and(
        child_data_length_shifted,
        context.field_const(u64::MAX as u64),
        "balance_call_child_data_length",
    );
    context.write_abi_data(child_data_offset, child_data_length, AddressSpace::Child);

    let result_status_code_pointer = unsafe {
        context.builder().build_gep(
            result_pointer.into_pointer_value(),
            &[
                context.field_const(0),
                context
                    .integer_type(compiler_common::BITLENGTH_X32)
                    .const_int(1, false),
            ],
            "balance_call_result_status_code_pointer",
        )
    };
    let result_status_code_boolean = context.build_load(
        result_status_code_pointer,
        "balance_call_result_status_code_boolean",
    );
    let return_pointer = context.build_alloca(context.field_type(), "balance_call_return_pointer");
    context.build_store(return_pointer, context.field_const(0));
    context.build_conditional_branch(
        result_status_code_boolean.into_int_value(),
        balance_call_success_block,
        balance_call_join_block,
    );

    context.set_basic_block(balance_call_success_block);
    let child_data_pointer = context.access_memory(
        child_data_offset,
        AddressSpace::Child,
        "balance_call_child_pointer",
    );
    let child_data_value = context.build_load(child_data_pointer, "balance_call_child_address");
    context.build_store(return_pointer, child_data_value);
    context.build_unconditional_branch(balance_call_join_block);

    context.set_basic_block(balance_call_join_block);
    let result = context.build_load(return_pointer, "balance_call_result");
    Ok(Some(result))
}
