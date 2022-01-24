//!
//! Translates a contract call.
//!

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
pub fn call<'ctx, 'dep, D>(
    context: &mut Context<'ctx, 'dep, D>,
    call_type: IntrinsicFunction,
    address: inkwell::values::IntValue<'ctx>,
    value: Option<inkwell::values::IntValue<'ctx>>,
    input_offset: inkwell::values::IntValue<'ctx>,
    input_size: inkwell::values::IntValue<'ctx>,
    output_offset: inkwell::values::IntValue<'ctx>,
    output_size: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    if let Some(value) = value {
        crate::evm::check_value_zero(context, value);
    }

    branch_identity(context, address, output_offset, input_offset, output_size)?;

    let intrinsic = context.get_intrinsic_function(IntrinsicFunction::SwitchContext);
    context.build_call(intrinsic, &[], "contract_call_switch_context");

    let child_pointer_header = context.access_memory(
        context.field_const(
            (compiler_common::ABI_MEMORY_OFFSET_HEADER * compiler_common::SIZE_FIELD) as u64,
        ),
        AddressSpace::Child,
        "contract_call_child_pointer_header",
    );
    context.build_store(child_pointer_header, input_size);

    let destination = context.access_memory(
        context.field_const(
            (compiler_common::ABI_MEMORY_OFFSET_DATA * compiler_common::SIZE_FIELD) as u64,
        ),
        AddressSpace::Child,
        "contract_call_child_input_destination",
    );
    let source = context.access_memory(
        input_offset,
        AddressSpace::Heap,
        "contract_call_child_input_source",
    );

    context.build_memcpy(
        IntrinsicFunction::MemoryCopyToChild,
        destination,
        source,
        input_size,
        "contract_call_memcpy_to_child",
    );

    let intrinsic = context.get_intrinsic_function(call_type);
    let call_definition = context.builder().build_left_shift(
        address,
        context.field_const((compiler_common::BITLENGTH_X32) as u64),
        "",
    );
    let is_call_successful = context
        .build_call(
            intrinsic,
            &[call_definition.as_basic_value_enum()],
            "contract_call_external",
        )
        .expect("IntrinsicFunction always returns a flag");

    let source = context.access_memory(
        context.field_const(
            (compiler_common::ABI_MEMORY_OFFSET_DATA * compiler_common::SIZE_FIELD) as u64,
        ),
        AddressSpace::Child,
        "contract_call_output_source",
    );
    let destination = context.access_memory(
        output_offset,
        AddressSpace::Heap,
        "contract_call_output_pointer",
    );

    context.build_memcpy(
        IntrinsicFunction::MemoryCopyFromChild,
        destination,
        source,
        output_size,
        "contract_call_memcpy_from_child",
    );

    Ok(Some(is_call_successful))
}

///
/// Translates a linker symbol.
///
pub fn linker_symbol<'ctx, 'dep, D>(
    context: &mut Context<'ctx, 'dep, D>,
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
/// Generates a memcopy call for the Identity precompile.
///
fn branch_identity<'ctx, 'dep, D>(
    context: &mut Context<'ctx, 'dep, D>,
    address: inkwell::values::IntValue<'ctx>,
    destination: inkwell::values::IntValue<'ctx>,
    source: inkwell::values::IntValue<'ctx>,
    size: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<()>
where
    D: Dependency,
{
    let identity_block = context.append_basic_block("contract_call_identity_block");
    let join_block = context.append_basic_block("contract_call_join_block");

    let is_address_identity = context.builder().build_int_compare(
        inkwell::IntPredicate::EQ,
        address,
        context.field_const_str(compiler_common::ABI_ADDRESS_IDENTITY),
        "contract_call_is_address_identity",
    );

    let destination = context.access_memory(
        destination,
        AddressSpace::Heap,
        "contract_call_identity_destination",
    );
    let source = context.access_memory(source, AddressSpace::Heap, "contract_call_identity_source");

    context.build_conditional_branch(is_address_identity, identity_block, join_block);

    context.set_basic_block(identity_block);
    context.build_memcpy(
        IntrinsicFunction::MemoryCopy,
        destination,
        source,
        size,
        "contract_call_memcpy_to_child",
    );
    context.build_unconditional_branch(join_block);

    context.set_basic_block(join_block);

    Ok(())
}
