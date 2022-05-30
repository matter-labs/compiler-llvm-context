//!
//! Translates a contract call.
//!

use inkwell::types::BasicType;
use inkwell::values::BasicValue;

use crate::context::address_space::AddressSpace;
use crate::context::argument::Argument;
use crate::context::function::intrinsic::Intrinsic as IntrinsicFunction;
use crate::context::Context;
use crate::Dependency;

///
/// Translates a contract call.
///
#[allow(clippy::too_many_arguments)]
pub fn call<'ctx, D>(
    context: &mut Context<'ctx, D>,
    function: inkwell::values::FunctionValue<'ctx>,
    gas: inkwell::values::IntValue<'ctx>,
    address: inkwell::values::IntValue<'ctx>,
    value: Option<inkwell::values::IntValue<'ctx>>,
    input_offset: inkwell::values::IntValue<'ctx>,
    input_length: inkwell::values::IntValue<'ctx>,
    output_offset: inkwell::values::IntValue<'ctx>,
    output_length: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let identity_block = context.append_basic_block("contract_call_identity_block");
    let tol1_block = context.append_basic_block("contract_call_toL1_block");
    let code_source_block = context.append_basic_block("contract_call_code_source_block");
    let precompile_block = context.append_basic_block("contract_call_precompile_block");
    let meta_block = context.append_basic_block("contract_call_meta_block");
    let mimic_call_block = context.append_basic_block("contract_call_mimic_call_block");
    let system_call_block = context.append_basic_block("contract_call_system_call_block");
    let ordinary_block = context.append_basic_block("contract_call_ordinary_block");
    let join_block = context.append_basic_block("contract_call_join_block");

    let result_pointer = context.build_alloca(context.field_type(), "contract_call_result_pointer");
    context.build_store(result_pointer, context.field_const(0));

    context.builder().build_switch(
        address,
        ordinary_block,
        &[
            (
                context.field_const_str(compiler_common::SOLIDITY_ADDRESS_IDENTITY),
                identity_block,
            ),
            (
                context.field_const_str(compiler_common::ABI_ADDRESS_TO_L1),
                tol1_block,
            ),
            (
                context.field_const_str(compiler_common::ABI_ADDRESS_CODE_ADDRESS),
                code_source_block,
            ),
            (
                context.field_const_str(compiler_common::ABI_ADDRESS_PRECOMPILE),
                precompile_block,
            ),
            (
                context.field_const_str(compiler_common::ABI_ADDRESS_META),
                meta_block,
            ),
            (
                context.field_const_str(compiler_common::ABI_ADDRESS_MIMIC_CALL),
                mimic_call_block,
            ),
            (
                context.field_const_str(compiler_common::ABI_ADDRESS_SYSTEM_CALL),
                system_call_block,
            ),
        ],
    );

    {
        context.set_basic_block(identity_block);
        let result = call_identity(context, output_offset, input_offset, output_length)?;
        context.build_store(result_pointer, result);
        context.build_unconditional_branch(join_block);
    }

    {
        context.set_basic_block(tol1_block);
        let in_0 = value.unwrap_or_else(|| context.field_const(0));
        let in_1 = input_offset;

        let contract_call_tol1_is_first_block =
            context.append_basic_block("contract_call_toL1_is_first_block");
        let contract_call_tol1_is_not_first_block =
            context.append_basic_block("contract_call_toL1_is_not_first_block");

        let is_first = gas;
        let is_first_equals_zero = context.builder().build_int_compare(
            inkwell::IntPredicate::EQ,
            is_first,
            context.field_const(0),
            "contract_call_toL1_is_first_equals_zero",
        );
        context.build_conditional_branch(
            is_first_equals_zero,
            contract_call_tol1_is_not_first_block,
            contract_call_tol1_is_first_block,
        );

        {
            context.set_basic_block(contract_call_tol1_is_not_first_block);
            let is_first = context.field_const(0);
            context.build_call(
                context.get_intrinsic_function(IntrinsicFunction::ToL1),
                &[
                    in_0.as_basic_value_enum(),
                    in_1.as_basic_value_enum(),
                    is_first.as_basic_value_enum(),
                ],
                "contract_call_simulation_tol1",
            );
            context.build_unconditional_branch(join_block);
        }

        {
            context.set_basic_block(contract_call_tol1_is_first_block);
            let is_first = context.field_const(1);
            context.build_call(
                context.get_intrinsic_function(IntrinsicFunction::ToL1),
                &[
                    in_0.as_basic_value_enum(),
                    in_1.as_basic_value_enum(),
                    is_first.as_basic_value_enum(),
                ],
                "contract_call_simulation_tol1",
            );
            context.build_unconditional_branch(join_block);
        }
    }

    {
        context.set_basic_block(code_source_block);
        let result = context
            .build_call(
                context.get_intrinsic_function(IntrinsicFunction::CodeSource),
                &[],
                "contract_call_simulation_code_source",
            )
            .expect("Always exists");
        context.build_store(result_pointer, result);
        context.build_unconditional_branch(join_block);
    }

    {
        context.set_basic_block(precompile_block);
        let in_0 = gas;
        let ergs_left = input_offset;
        let result = context
            .build_call(
                context.get_intrinsic_function(IntrinsicFunction::Precompile),
                &[in_0.as_basic_value_enum(), ergs_left.as_basic_value_enum()],
                "contract_call_simulation_precompile",
            )
            .expect("Always exists");
        context.build_store(result_pointer, result);
        context.build_unconditional_branch(join_block);
    }

    {
        context.set_basic_block(meta_block);
        let result = context
            .build_call(
                context.get_intrinsic_function(IntrinsicFunction::Meta),
                &[],
                "contract_call_simulation_meta",
            )
            .expect("Always exists");
        context.build_store(result_pointer, result);
        context.build_unconditional_branch(join_block);
    }

    {
        context.set_basic_block(mimic_call_block);
        let address = gas;
        let mimic = value.unwrap_or_else(|| context.field_const(0));
        let abi_data = input_offset;
        let result = call_mimic(
            context,
            context.runtime.mimic_call,
            address,
            mimic,
            abi_data,
        )?;
        context.build_store(result_pointer, result);
        context.build_unconditional_branch(join_block);
    }

    {
        context.set_basic_block(system_call_block);
        let address = gas;
        let abi_data = input_offset;

        let system_far_call_block = context.append_basic_block("system_far_call_block");
        let system_delegate_call_block = context.append_basic_block("system_delegate_call_block");

        let is_delegate = input_length;
        let is_delegate_equals_zero = context.builder().build_int_compare(
            inkwell::IntPredicate::EQ,
            is_delegate,
            context.field_const(0),
            "system_far_call_is_delegate_equals_zero",
        );
        context.build_conditional_branch(
            is_delegate_equals_zero,
            system_far_call_block,
            system_delegate_call_block,
        );

        {
            context.set_basic_block(system_far_call_block);
            let result = call_system(
                context,
                context.runtime.far_call,
                address,
                abi_data,
                output_offset,
                output_length,
            )?;
            context.build_store(result_pointer, result);
            context.build_unconditional_branch(join_block);
        }

        {
            context.set_basic_block(system_delegate_call_block);
            let result = call_system(
                context,
                context.runtime.delegate_call,
                address,
                abi_data,
                output_offset,
                output_length,
            )?;
            context.build_store(result_pointer, result);
            context.build_unconditional_branch(join_block);
        }
    }

    context.set_basic_block(ordinary_block);
    if let Some(value) = value {
        crate::evm::check_value_zero(context, value);
    }
    let result = call_default(
        context,
        function,
        address,
        input_offset,
        input_length,
        output_offset,
        output_length,
    )?;
    context.build_store(result_pointer, result);
    context.build_unconditional_branch(join_block);

    context.set_basic_block(join_block);
    let result = context.build_load(result_pointer, "contract_call_result");

    Ok(Some(result))
}

///
/// Translates a linker symbol.
///
pub fn linker_symbol<'ctx, D>(
    context: &mut Context<'ctx, D>,
    mut arguments: [Argument<'ctx>; 1],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let path = arguments[0]
        .original
        .take()
        .ok_or_else(|| anyhow::anyhow!("Linker symbol literal is missing"))?;

    Ok(Some(
        context
            .resolve_library(path.as_str())?
            .as_basic_value_enum(),
    ))
}

///
/// Generates a default contract call.
///
fn call_default<'ctx, D>(
    context: &mut Context<'ctx, D>,
    function: inkwell::values::FunctionValue<'ctx>,
    address: inkwell::values::IntValue<'ctx>,
    input_offset: inkwell::values::IntValue<'ctx>,
    input_length: inkwell::values::IntValue<'ctx>,
    output_offset: inkwell::values::IntValue<'ctx>,
    output_length: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<inkwell::values::BasicValueEnum<'ctx>>
where
    D: Dependency,
{
    let input_length_shifted = context.builder().build_left_shift(
        input_length,
        context.field_const(compiler_common::BITLENGTH_X64 as u64),
        "contract_call_input_length_shifted",
    );
    let abi_data = context.builder().build_int_add(
        input_length_shifted,
        input_offset,
        "contract_call_abi_data",
    );

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
    let result_pointer = context.build_alloca(result_type, "contract_call_result_pointer");

    let result_pointer = context
        .build_invoke(
            function,
            &[
                address.as_basic_value_enum(),
                abi_data.as_basic_value_enum(),
                result_pointer.as_basic_value_enum(),
            ],
            "contract_call_external",
        )
        .expect("IntrinsicFunction always returns a flag");

    let result_abi_data_pointer = unsafe {
        context.builder().build_gep(
            result_pointer.into_pointer_value(),
            &[
                context.field_const(0),
                context
                    .integer_type(compiler_common::BITLENGTH_X32)
                    .const_zero(),
            ],
            "contract_call_external_result_abi_data_pointer",
        )
    };
    let result_abi_data = context.build_load(
        result_abi_data_pointer,
        "contract_call_external_result_abi_data",
    );

    let result_status_code_pointer = unsafe {
        context.builder().build_gep(
            result_pointer.into_pointer_value(),
            &[
                context.field_const(0),
                context
                    .integer_type(compiler_common::BITLENGTH_X32)
                    .const_int(1, false),
            ],
            "contract_call_external_result_status_code_pointer",
        )
    };
    let result_status_code_boolean = context.build_load(
        result_status_code_pointer,
        "contract_call_external_result_status_code_boolean",
    );
    let result_status_code = context.builder().build_int_z_extend_or_bit_cast(
        result_status_code_boolean.into_int_value(),
        context.field_type(),
        "contract_call_external_result_status_code",
    );

    let child_data_offset = context.builder().build_and(
        result_abi_data.into_int_value(),
        context.field_const(u64::MAX as u64),
        "contract_call_child_data_offset",
    );
    let child_data_length_shifted = context.builder().build_right_shift(
        result_abi_data.into_int_value(),
        context.field_const(compiler_common::BITLENGTH_X64 as u64),
        false,
        "contract_call_child_data_length_shifted",
    );
    let child_data_length = context.builder().build_and(
        child_data_length_shifted,
        context.field_const(u64::MAX as u64),
        "contract_call_child_data_length",
    );
    let source = context.access_memory(
        child_data_offset,
        AddressSpace::Child,
        "contract_call_source",
    );

    let destination = context.access_memory(
        output_offset,
        AddressSpace::Heap,
        "contract_call_destination",
    );

    context.build_memcpy(
        IntrinsicFunction::MemoryCopyFromChild,
        destination,
        source,
        output_length,
        "contract_call_memcpy_from_child",
    );

    context.write_abi_data(child_data_offset, child_data_length, AddressSpace::Child);

    Ok(result_status_code.as_basic_value_enum())
}

///
/// Generates a mimic call.
///
fn call_mimic<'ctx, D>(
    context: &mut Context<'ctx, D>,
    function: inkwell::values::FunctionValue<'ctx>,
    address: inkwell::values::IntValue<'ctx>,
    mimic: inkwell::values::IntValue<'ctx>,
    abi_data: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<inkwell::values::BasicValueEnum<'ctx>>
where
    D: Dependency,
{
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
    let result_pointer = context.build_alloca(result_type, "mimic_call_result_pointer");

    let result_pointer = context
        .build_invoke(
            function,
            &[
                address.as_basic_value_enum(),
                abi_data.as_basic_value_enum(),
                mimic.as_basic_value_enum(),
                result_pointer.as_basic_value_enum(),
            ],
            "mimic_call_external",
        )
        .expect("IntrinsicFunction always returns a flag");

    let result_abi_data_pointer = unsafe {
        context.builder().build_gep(
            result_pointer.into_pointer_value(),
            &[
                context.field_const(0),
                context
                    .integer_type(compiler_common::BITLENGTH_X32)
                    .const_zero(),
            ],
            "mimic_call_external_result_abi_data_pointer",
        )
    };
    let result_abi_data = context.build_load(
        result_abi_data_pointer,
        "mimic_call_external_result_abi_data",
    );

    let result_status_code_pointer = unsafe {
        context.builder().build_gep(
            result_pointer.into_pointer_value(),
            &[
                context.field_const(0),
                context
                    .integer_type(compiler_common::BITLENGTH_X32)
                    .const_int(1, false),
            ],
            "mimic_call_external_result_status_code_pointer",
        )
    };
    let result_status_code_boolean = context.build_load(
        result_status_code_pointer,
        "mimic_call_external_result_status_code_boolean",
    );
    let result_status_code = context.builder().build_int_z_extend_or_bit_cast(
        result_status_code_boolean.into_int_value(),
        context.field_type(),
        "mimic_call_external_result_status_code",
    );

    let child_data_offset = context.builder().build_and(
        result_abi_data.into_int_value(),
        context.field_const(u64::MAX as u64),
        "mimic_call_child_data_offset",
    );
    let child_data_length_shifted = context.builder().build_right_shift(
        result_abi_data.into_int_value(),
        context.field_const(compiler_common::BITLENGTH_X64 as u64),
        false,
        "mimic_call_child_data_length_shifted",
    );
    let child_data_length = context.builder().build_and(
        child_data_length_shifted,
        context.field_const(u64::MAX as u64),
        "mimic_call_child_data_length",
    );

    context.write_abi_data(child_data_offset, child_data_length, AddressSpace::Child);

    Ok(result_status_code.as_basic_value_enum())
}

///
/// Generates a system call.
///
fn call_system<'ctx, D>(
    context: &mut Context<'ctx, D>,
    function: inkwell::values::FunctionValue<'ctx>,
    address: inkwell::values::IntValue<'ctx>,
    abi_data: inkwell::values::IntValue<'ctx>,
    output_offset: inkwell::values::IntValue<'ctx>,
    output_length: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<inkwell::values::BasicValueEnum<'ctx>>
where
    D: Dependency,
{
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
    let result_pointer = context.build_alloca(result_type, "system_far_call_result_pointer");

    let result_pointer = context
        .build_invoke(
            function,
            &[
                address.as_basic_value_enum(),
                abi_data.as_basic_value_enum(),
                result_pointer.as_basic_value_enum(),
            ],
            "system_far_call_external",
        )
        .expect("IntrinsicFunction always returns a flag");

    let result_abi_data_pointer = unsafe {
        context.builder().build_gep(
            result_pointer.into_pointer_value(),
            &[
                context.field_const(0),
                context
                    .integer_type(compiler_common::BITLENGTH_X32)
                    .const_zero(),
            ],
            "system_far_call_external_result_abi_data_pointer",
        )
    };
    let result_abi_data = context.build_load(
        result_abi_data_pointer,
        "system_far_call_external_result_abi_data",
    );

    let result_status_code_pointer = unsafe {
        context.builder().build_gep(
            result_pointer.into_pointer_value(),
            &[
                context.field_const(0),
                context
                    .integer_type(compiler_common::BITLENGTH_X32)
                    .const_int(1, false),
            ],
            "system_far_call_external_result_status_code_pointer",
        )
    };
    let result_status_code_boolean = context.build_load(
        result_status_code_pointer,
        "system_far_call_external_result_status_code_boolean",
    );
    let result_status_code = context.builder().build_int_z_extend_or_bit_cast(
        result_status_code_boolean.into_int_value(),
        context.field_type(),
        "system_far_call_external_result_status_code",
    );

    let child_data_offset = context.builder().build_and(
        result_abi_data.into_int_value(),
        context.field_const(u64::MAX as u64),
        "system_far_call_child_data_offset",
    );
    let child_data_length_shifted = context.builder().build_right_shift(
        result_abi_data.into_int_value(),
        context.field_const(compiler_common::BITLENGTH_X64 as u64),
        false,
        "system_far_call_child_data_length_shifted",
    );
    let child_data_length = context.builder().build_and(
        child_data_length_shifted,
        context.field_const(u64::MAX as u64),
        "system_far_call_child_data_length",
    );
    let source = context.access_memory(
        child_data_offset,
        AddressSpace::Child,
        "system_far_call_source",
    );

    let destination = context.access_memory(
        output_offset,
        AddressSpace::Heap,
        "system_far_call_destination",
    );

    context.build_memcpy(
        IntrinsicFunction::MemoryCopyFromChild,
        destination,
        source,
        output_length,
        "system_far_call_memcpy_from_child",
    );

    context.write_abi_data(child_data_offset, child_data_length, AddressSpace::Child);

    Ok(result_status_code.as_basic_value_enum())
}

///
/// Generates a memcopy call for the Identity precompile.
///
fn call_identity<'ctx, D>(
    context: &mut Context<'ctx, D>,
    destination: inkwell::values::IntValue<'ctx>,
    source: inkwell::values::IntValue<'ctx>,
    size: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<inkwell::values::BasicValueEnum<'ctx>>
where
    D: Dependency,
{
    let destination = context.access_memory(
        destination,
        AddressSpace::Heap,
        "contract_call_identity_destination",
    );
    let source = context.access_memory(source, AddressSpace::Heap, "contract_call_identity_source");

    context.build_memcpy(
        IntrinsicFunction::MemoryCopy,
        destination,
        source,
        size,
        "contract_call_memcpy_to_child",
    );

    Ok(context.field_const(1).as_basic_value_enum())
}
