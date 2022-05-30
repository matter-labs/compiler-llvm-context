//!
//! Translates the contract creation instructions.
//!

use inkwell::types::BasicType;
use inkwell::values::BasicValue;

use crate::context::Context;
use crate::AddressSpace;
use crate::Dependency;

///
/// Translates the contract `create` instruction.
///
pub fn create<'ctx, D>(
    context: &mut Context<'ctx, D>,
    value: inkwell::values::IntValue<'ctx>,
    input_offset: inkwell::values::IntValue<'ctx>,
    input_length: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    crate::evm::check_value_zero(context, value);

    let address = call_precompile(
        context,
        input_offset,
        input_length,
        "create(bytes32,bytes32,bytes)",
        None,
    )?;

    Ok(Some(address.as_basic_value_enum()))
}

///
/// Translates the contract `create2` instruction.
///
pub fn create2<'ctx, D>(
    context: &mut Context<'ctx, D>,
    value: inkwell::values::IntValue<'ctx>,
    input_offset: inkwell::values::IntValue<'ctx>,
    input_length: inkwell::values::IntValue<'ctx>,
    salt: Option<inkwell::values::IntValue<'ctx>>,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    crate::evm::check_value_zero(context, value);

    let address = call_precompile(
        context,
        input_offset,
        input_length,
        "create2(bytes32,bytes32,bytes)",
        salt,
    )?;

    Ok(Some(address.as_basic_value_enum()))
}

///
/// Translates the contract hash instruction, which is actually used to set the hash of the contract
/// being created, or other related auxiliary data.
///
/// `dataoffset` in Yul, `PUSH [$]` in legacy assembly.
///
pub fn contract_hash<'ctx, D>(
    context: &mut Context<'ctx, D>,
    identifier: String,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let parent = context.module().get_name().to_str().expect("Always valid");

    if identifier.ends_with("_deployed") || identifier.as_str() == parent {
        return Ok(Some(context.field_const(0).as_basic_value_enum()));
    }

    let hash_value = context
        .compile_dependency(identifier.as_str())
        .map(|hash| context.field_const_str(hash.as_str()))
        .map(inkwell::values::BasicValueEnum::IntValue)?;

    Ok(Some(hash_value))
}

///
/// Translates the deployer call header size instruction, Usually, the header consists of:
/// - the deployer contract method signature
/// - the salt if the call is `create2`, or zero if the call is `create1`
/// - the hash of the bytecode of the contract whose instance is being created
///
/// If the call is `create1`, the space for the salt is still allocated, because the memory for the
/// header is allocated before it is known which version of `create` is going to be used.
///
/// Concerning AST, it looks like `datasize` in Yul, and `PUSH #[$]` in the EVM legacy assembly.
///
pub fn contract_hash_size<'ctx, D>(
    context: &mut Context<'ctx, D>,
    identifier: String,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let parent = context.module().get_name().to_str().expect("Always valid");

    if identifier.ends_with("_deployed") || identifier.as_str() == parent {
        return Ok(Some(context.field_const(0).as_basic_value_enum()));
    }

    Ok(Some(
        context
            .field_const((compiler_common::SIZE_X32 + compiler_common::SIZE_FIELD * 4) as u64)
            .as_basic_value_enum(),
    ))
}

///
/// Calls the `create` precompile, which returns the newly deployed contract address.
///
fn call_precompile<'ctx, D>(
    context: &mut Context<'ctx, D>,
    input_offset: inkwell::values::IntValue<'ctx>,
    input_length: inkwell::values::IntValue<'ctx>,
    signature: &'static str,
    salt: Option<inkwell::values::IntValue<'ctx>>,
) -> anyhow::Result<inkwell::values::BasicValueEnum<'ctx>>
where
    D: Dependency,
{
    let deployer_call_success_block = context.append_basic_block("deployer_call_success_block");
    let deployer_call_join_block = context.append_basic_block("deployer_call_join_block");

    let address = context.field_const_str_hex(compiler_common::ABI_ADDRESS_CONTRACT_DEPLOYER);

    let input_length_shifted = context.builder().build_left_shift(
        input_length,
        context.field_const(compiler_common::BITLENGTH_X64 as u64),
        "deployer_call_input_length_shifted",
    );
    let abi_data = context.builder().build_int_add(
        input_length_shifted,
        input_offset,
        "deployer_call_abi_data",
    );

    let signature_hash = crate::hashes::keccak256(signature.as_bytes());
    let signature_pointer = context.access_memory(
        input_offset,
        AddressSpace::Heap,
        "deployer_call_signature_pointer",
    );
    let signature_value = context.field_const_str(signature_hash.as_str());
    context.build_store(signature_pointer, signature_value);

    let salt_offset = context.builder().build_int_add(
        input_offset,
        context.field_const(compiler_common::SIZE_X32 as u64),
        "deployer_call_salt_offset",
    );
    let salt_pointer = context.access_memory(
        salt_offset,
        AddressSpace::Heap,
        "deployer_call_salt_pointer",
    );
    let salt_value = salt.unwrap_or_else(|| context.field_const(0));
    context.build_store(salt_pointer, salt_value);

    let arguments_offset_offset = context.builder().build_int_add(
        salt_offset,
        context.field_const((compiler_common::SIZE_FIELD * 2) as u64),
        "deployer_call_arguments_offset_offset",
    );
    let arguments_offset_pointer = context.access_memory(
        arguments_offset_offset,
        AddressSpace::Heap,
        "deployer_call_arguments_offset_pointer",
    );
    context.build_store(
        arguments_offset_pointer,
        context.field_const((compiler_common::SIZE_FIELD * 3) as u64),
    );

    let arguments_length_offset = context.builder().build_int_add(
        arguments_offset_offset,
        context.field_const(compiler_common::SIZE_FIELD as u64),
        "deployer_call_arguments_length_offset",
    );
    let arguments_length_pointer = context.access_memory(
        arguments_length_offset,
        AddressSpace::Heap,
        "deployer_call_arguments_length_pointer",
    );
    let arguments_length_value = context.builder().build_int_sub(
        input_length,
        context.field_const((compiler_common::SIZE_X32 + compiler_common::SIZE_FIELD * 4) as u64),
        "deployer_call_arguments_length",
    );
    context.build_store(arguments_length_pointer, arguments_length_value);

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
    let result_pointer = context.build_alloca(result_type, "deployer_call_result_pointer");

    let result_pointer = context
        .build_invoke(
            context.runtime.far_call,
            &[
                address.as_basic_value_enum(),
                abi_data.as_basic_value_enum(),
                result_pointer.as_basic_value_enum(),
            ],
            "deployer_call",
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
            "deployer_call_result_abi_data_pointer",
        )
    };
    let result_abi_data =
        context.build_load(result_abi_data_pointer, "deployer_call_result_abi_data");
    let child_data_offset = context.builder().build_and(
        result_abi_data.into_int_value(),
        context.field_const(u64::MAX as u64),
        "deployer_call_child_data_offset",
    );
    let child_data_length_shifted = context.builder().build_right_shift(
        result_abi_data.into_int_value(),
        context.field_const(compiler_common::BITLENGTH_X64 as u64),
        false,
        "deployer_call_child_data_length_shifted",
    );
    let child_data_length = context.builder().build_and(
        child_data_length_shifted,
        context.field_const(u64::MAX as u64),
        "deployer_call_child_data_length",
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
            "deployer_call_result_status_code_pointer",
        )
    };
    let result_status_code_boolean = context.build_load(
        result_status_code_pointer,
        "deployer_call_result_status_code_boolean",
    );
    let return_pointer = context.build_alloca(context.field_type(), "deployer_call_return_pointer");
    context.build_store(return_pointer, context.field_const(0));
    context.build_conditional_branch(
        result_status_code_boolean.into_int_value(),
        deployer_call_success_block,
        deployer_call_join_block,
    );

    context.set_basic_block(deployer_call_success_block);
    let child_data_pointer = context.access_memory(
        child_data_offset,
        AddressSpace::Child,
        "deployer_call_child_pointer",
    );
    let child_address = context.build_load(child_data_pointer, "deployer_call_child_address");
    context.build_store(return_pointer, child_address);
    context.build_unconditional_branch(deployer_call_join_block);

    context.set_basic_block(deployer_call_join_block);
    let result = context.build_load(return_pointer, "deployer_call_result");
    Ok(result)
}
