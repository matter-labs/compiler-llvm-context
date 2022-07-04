//!
//! Translates some custom external call requests.
//!

use inkwell::types::BasicType;
use inkwell::values::BasicValue;

use crate::context::address_space::AddressSpace;
use crate::context::Context;
use crate::Dependency;

///
/// Generates a custom request to a system contract.
///
pub fn request<'ctx, D>(
    context: &mut Context<'ctx, D>,
    address: inkwell::values::IntValue<'ctx>,
    signature: &'static str,
    arguments: Vec<inkwell::values::IntValue<'ctx>>,
) -> anyhow::Result<inkwell::values::BasicValueEnum<'ctx>>
where
    D: Dependency,
{
    let call_success_block = context.append_basic_block("call_success_block");
    let call_join_block = context.append_basic_block("call_join_block");

    let input_offset = context.field_const(
        (compiler_common::ABI_MEMORY_OFFSET_ARBITRARY_EXTERNAL_CALL_SPACE
            * compiler_common::SIZE_FIELD) as u64,
    );
    let input_length_shifted = context.builder().build_left_shift(
        context.field_const((compiler_common::SIZE_X32 + compiler_common::SIZE_FIELD) as u64),
        context.field_const(compiler_common::BITLENGTH_X64 as u64),
        "call_input_length_shifted",
    );
    let abi_data =
        context
            .builder()
            .build_int_add(input_length_shifted, input_offset, "call_abi_data");

    let signature_hash = crate::hashes::keccak256(signature.as_bytes());
    let signature_pointer =
        context.access_memory(input_offset, AddressSpace::Heap, "call_signature_pointer");
    let signature_value = context.field_const_str(signature_hash.as_str());
    context.build_store(signature_pointer, signature_value);

    for (index, argument) in arguments.into_iter().enumerate() {
        let arguments_offset = context.builder().build_int_add(
            input_offset,
            context.field_const(
                (compiler_common::SIZE_X32 + index * compiler_common::SIZE_FIELD) as u64,
            ),
            format!("call_argument_{}_offset", index).as_str(),
        );
        let arguments_pointer = context.access_memory(
            arguments_offset,
            AddressSpace::Heap,
            format!("call_argument_{}_pointer", index).as_str(),
        );
        context.build_store(arguments_pointer, argument);
    }

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
    let result_pointer = context.build_alloca(result_type, "call_result_pointer");

    let result_pointer = context
        .build_call(
            context.runtime.static_call,
            &[
                address.as_basic_value_enum(),
                abi_data.as_basic_value_enum(),
                result_pointer.as_basic_value_enum(),
            ],
            "call",
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
            "call_result_abi_data_pointer",
        )
    };
    let result_abi_data = context.build_load(result_abi_data_pointer, "call_result_abi_data");
    let child_data_offset = context.builder().build_and(
        result_abi_data.into_int_value(),
        context.field_const(u64::MAX as u64),
        "call_child_data_offset",
    );
    let child_data_length_shifted = context.builder().build_right_shift(
        result_abi_data.into_int_value(),
        context.field_const(compiler_common::BITLENGTH_X64 as u64),
        false,
        "call_child_data_length_shifted",
    );
    let child_data_length = context.builder().build_and(
        child_data_length_shifted,
        context.field_const(u64::MAX as u64),
        "call_child_data_length",
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
            "call_result_status_code_pointer",
        )
    };
    let result_status_code_boolean = context.build_load(
        result_status_code_pointer,
        "call_result_status_code_boolean",
    );
    let return_pointer = context.build_alloca(context.field_type(), "call_return_pointer");
    context.build_store(return_pointer, context.field_const(0));
    context.build_conditional_branch(
        result_status_code_boolean.into_int_value(),
        call_success_block,
        call_join_block,
    );

    context.set_basic_block(call_success_block);
    let child_data_pointer =
        context.access_memory(child_data_offset, AddressSpace::Child, "call_child_pointer");
    let child_data_value = context.build_load(child_data_pointer, "call_child_address");
    context.build_store(return_pointer, child_data_value);
    context.build_unconditional_branch(call_join_block);

    context.set_basic_block(call_join_block);
    let result = context.build_load(return_pointer, "call_result");
    Ok(result)
}
