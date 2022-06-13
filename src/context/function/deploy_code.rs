//!
//! The LLVM deploy code function.
//!

use std::marker::PhantomData;

use inkwell::types::BasicType;
use inkwell::values::BasicValue;

use crate::context::address_space::AddressSpace;
use crate::context::function::runtime::Runtime;
use crate::context::function::Function;
use crate::context::Context;
use crate::Dependency;
use crate::WriteLLVM;

///
/// The LLVM deploy code function.
///
#[derive(Debug)]
pub struct DeployCode<B, D>
where
    B: WriteLLVM<D>,
    D: Dependency,
{
    /// The deploy code AST representation.
    inner: B,
    /// The runtime code hash.
    runtime_code_hash: String,
    /// The `D` phantom data.
    _pd: PhantomData<D>,
}

impl<B, D> DeployCode<B, D>
where
    B: WriteLLVM<D>,
    D: Dependency,
{
    ///
    /// A shortcut constructor.
    ///
    pub fn new(inner: B, runtime_code_hash: String) -> Self {
        Self {
            inner,
            runtime_code_hash,
            _pd: PhantomData::default(),
        }
    }
}

impl<B, D> WriteLLVM<D> for DeployCode<B, D>
where
    B: WriteLLVM<D>,
    D: Dependency,
{
    fn declare(&mut self, context: &mut Context<D>) -> anyhow::Result<()> {
        let function_type =
            context.function_type(1, vec![context.field_type().as_basic_type_enum(); 2]);
        context.add_function(
            Runtime::FUNCTION_DEPLOY_CODE,
            function_type,
            Some(inkwell::module::Linkage::External),
        );

        self.inner.declare(context)
    }

    fn into_llvm(self, context: &mut Context<D>) -> anyhow::Result<()> {
        let function = context
            .functions
            .get(Runtime::FUNCTION_DEPLOY_CODE)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Contract deploy code not found"))?;
        context.set_function(function);

        context.set_basic_block(context.function().entry_block);
        let calldata_offset = context
            .function()
            .value
            .get_nth_param(Function::ARGUMENT_INDEX_CALLDATA_OFFSET as u32)
            .expect("Always exists")
            .into_int_value();
        let calldata_offset = context.builder().build_and(
            calldata_offset,
            context.field_const(((1 << 24) - 1) as u64),
            "calldata_offset_masked",
        );
        let calldata_length = context
            .function()
            .value
            .get_nth_param(Function::ARGUMENT_INDEX_CALLDATA_LENGTH as u32)
            .expect("Always exists")
            .into_int_value();
        context.write_abi_data(calldata_offset, calldata_length, AddressSpace::Parent);

        let runtime_code_hash_pointer = context.access_memory(
            context.field_const(0),
            AddressSpace::Heap,
            "runtime_code_hash_pointer",
        );
        context.build_store(
            runtime_code_hash_pointer,
            context.field_const_str(self.runtime_code_hash.as_str()),
        );

        self.inner.into_llvm(context)?;
        match context
            .basic_block()
            .get_last_instruction()
            .map(|instruction| instruction.get_opcode())
        {
            Some(inkwell::values::InstructionOpcode::Br) => {}
            Some(inkwell::values::InstructionOpcode::Switch) => {}
            _ => context.build_unconditional_branch(context.function().return_block),
        }

        context.set_basic_block(context.function().return_block);
        let return_value = context
            .read_abi_data(AddressSpace::Parent)
            .as_basic_value_enum();
        context.build_return(Some(&return_value));

        Ok(())
    }
}
