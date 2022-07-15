//!
//! Translates the contract immutable operations.
//!

use crate::context::address_space::AddressSpace;
use crate::context::code_type::CodeType;
use crate::context::function::intrinsic::Intrinsic as IntrinsicFunction;
use crate::context::Context;
use crate::Dependency;

///
/// Translates the contract immutable load.
///
pub fn load<'ctx, D>(
    context: &mut Context<'ctx, D>,
    index: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    match context.code_type() {
        CodeType::Deploy => {
            let index_double = context.builder().build_int_mul(
                index,
                context.field_const(2),
                "immutable_load_index_double",
            );
            let offset_absolute = context.builder().build_int_add(
                index_double,
                context.field_const(
                    ((compiler_common::ABI_MEMORY_OFFSET_CONSTRUCTOR_RETURN_DATA + 3)
                        * compiler_common::SIZE_FIELD) as u64,
                ),
                "immutable_offset_absolute",
            );
            let immutable_pointer =
                context.access_memory(offset_absolute, AddressSpace::Heap, "immutable_pointer");
            let immutable_value = context.build_load(immutable_pointer, "immutable_value");
            Ok(Some(immutable_value))
        }
        CodeType::Runtime => {
            let code_address = context
                .build_call(
                    context.get_intrinsic_function(IntrinsicFunction::CodeSource),
                    &[],
                    "immutable_code_address",
                )
                .expect("Always exists")
                .into_int_value();
            crate::evm::contract::request::request(
                context,
                context.field_const_str(compiler_common::ABI_ADDRESS_IMMUTABLE_SIMULATOR),
                "getImmutable(address,uint256)",
                vec![code_address, index],
            )
            .map(Some)
        }
    }
}

///
/// Translates the contract immutable store.
///
pub fn store<'ctx, D>(
    context: &mut Context<'ctx, D>,
    index: inkwell::values::IntValue<'ctx>,
    value: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    match context.code_type() {
        CodeType::Deploy => {
            let index_double = context.builder().build_int_mul(
                index,
                context.field_const(2),
                "immutable_load_index_double",
            );
            let index_offset_absolute = context.builder().build_int_add(
                index_double,
                context.field_const(
                    ((compiler_common::ABI_MEMORY_OFFSET_CONSTRUCTOR_RETURN_DATA + 2)
                        * compiler_common::SIZE_FIELD) as u64,
                ),
                "index_offset_absolute",
            );
            let index_offset_pointer = context.access_memory(
                index_offset_absolute,
                AddressSpace::Heap,
                "immutable_index_pointer",
            );
            context.build_store(index_offset_pointer, index);

            let value_offset_absolute = context.builder().build_int_add(
                index_offset_absolute,
                context.field_const(compiler_common::SIZE_FIELD as u64),
                "value_offset_absolute",
            );
            let value_offset_pointer = context.access_memory(
                value_offset_absolute,
                AddressSpace::Heap,
                "immutable_value_pointer",
            );
            context.build_store(value_offset_pointer, value);

            Ok(None)
        }
        CodeType::Runtime => Ok(None),
    }
}
