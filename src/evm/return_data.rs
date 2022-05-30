//!
//! Translates the return data instructions.
//!

use inkwell::values::BasicValue;

use crate::context::address_space::AddressSpace;
use crate::context::function::intrinsic::Intrinsic as IntrinsicFunction;
use crate::context::Context;
use crate::Dependency;

///
/// Translates the return data size.
///
pub fn size<'ctx, D>(
    context: &mut Context<'ctx, D>,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let length_pointer = context.access_memory(
        context.field_const(
            (compiler_common::ABI_MEMORY_OFFSET_RETURN_DATA_LENGTH * compiler_common::SIZE_FIELD)
                as u64,
        ),
        AddressSpace::Heap,
        "return_data_size_length_pointer",
    );
    let length = context.build_load(length_pointer, "return_data_value");

    Ok(Some(length.as_basic_value_enum()))
}

///
/// Translates the return data copy.
///
pub fn copy<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 3],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let destination = context.access_memory(
        arguments[0].into_int_value(),
        AddressSpace::Heap,
        "return_data_copy_destination_pointer",
    );

    let child_offset_pointer = context.access_memory(
        context.field_const(
            (compiler_common::ABI_MEMORY_OFFSET_RETURN_DATA_OFFSET * compiler_common::SIZE_FIELD)
                as u64,
        ),
        AddressSpace::Heap,
        "return_data_copy_child_offset_pointer",
    );
    let child_offset = context.build_load(child_offset_pointer, "return_data_copy_child_offset");
    let source_offset = context.builder().build_int_add(
        arguments[1].into_int_value(),
        child_offset.into_int_value(),
        "return_data_copy_source_offset",
    );
    let source = context.access_memory(
        source_offset,
        AddressSpace::Child,
        "return_data_copy_source_pointer",
    );

    let size = arguments[2].into_int_value();

    context.build_memcpy(
        IntrinsicFunction::MemoryCopyFromChild,
        destination,
        source,
        size,
        "return_data_copy_memcpy_from_child",
    );

    Ok(None)
}
