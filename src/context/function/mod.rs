//!
//! The LLVM generator function.
//!

pub mod block;
pub mod deploy_code;
pub mod evm_data;
pub mod intrinsic;
pub mod r#return;
pub mod runtime;
pub mod runtime_code;

use std::collections::HashMap;

use self::evm_data::EVMData;
use self::r#return::Return;

///
/// The LLVM generator function.
///
#[derive(Debug, Clone)]
pub struct Function<'ctx> {
    /// The name.
    pub name: String,
    /// The LLVM value.
    pub value: inkwell::values::FunctionValue<'ctx>,

    /// The entry block.
    pub entry_block: inkwell::basic_block::BasicBlock<'ctx>,
    /// The return/leave block.
    pub return_block: inkwell::basic_block::BasicBlock<'ctx>,

    /// The return value entity.
    pub r#return: Option<Return<'ctx>>,
    /// The stack representation.
    pub stack: HashMap<String, inkwell::values::PointerValue<'ctx>>,
    /// The block-local variables. They are still allocated at the beginning of the function,
    /// but their parent block must be known in order to pass the implicit arguments thereto.
    /// Is only used by the Vyper LLL IR compiler.
    pub label_arguments: HashMap<String, Vec<String>>,

    /// The EVM compiler data.
    pub evm_data: Option<EVMData<'ctx>>,
}

impl<'ctx> Function<'ctx> {
    /// The near call ABI function prefix.
    pub const ZKSYNC_NEAR_CALL_ABI_PREFIX: &'static str = "ZKSYNC_NEAR_CALL";

    /// The near call ABI exception handler name.
    pub const ZKSYNC_NEAR_CALL_ABI_EXCEPTION_HANDLER: &'static str = "ZKSYNC_CATCH_NEAR_CALL";

    /// The calldata offset entry argument index.
    pub const ARGUMENT_INDEX_CALLDATA_OFFSET: usize = 0;

    /// The calldata length entry argument index.
    pub const ARGUMENT_INDEX_CALLDATA_LENGTH: usize = 1;

    /// The stack hashmap default capacity.
    const STACK_HASHMAP_INITIAL_CAPACITY: usize = 64;

    ///
    /// A shortcut constructor.
    ///
    pub fn new(
        name: String,
        value: inkwell::values::FunctionValue<'ctx>,

        entry_block: inkwell::basic_block::BasicBlock<'ctx>,
        return_block: inkwell::basic_block::BasicBlock<'ctx>,

        r#return: Option<Return<'ctx>>,
    ) -> Self {
        Self {
            name,
            value,

            entry_block,
            return_block,

            r#return,
            stack: HashMap::with_capacity(Self::STACK_HASHMAP_INITIAL_CAPACITY),
            label_arguments: HashMap::new(),

            evm_data: None,
        }
    }

    ///
    /// Sets the function return data.
    ///
    pub fn set_return(&mut self, r#return: Return<'ctx>) {
        self.r#return = Some(r#return);
    }

    ///
    /// Returns the pointer to the function return value.
    ///
    /// # Panics
    /// If the pointer has not been set yet.
    ///
    pub fn return_pointer(&self) -> Option<inkwell::values::PointerValue<'ctx>> {
        self.r#return
            .as_ref()
            .expect("Always exists")
            .return_pointer()
    }

    ///
    /// Returns the EVM data reference.
    ///
    /// # Panics
    /// If the EVM data has not been initialized.
    ///
    pub fn evm(&self) -> &EVMData<'ctx> {
        self.evm_data
            .as_ref()
            .expect("The EVM data must have been initialized")
    }

    ///
    /// Returns the EVM data mutable reference.
    ///
    /// # Panics
    /// If the EVM data has not been initialized.
    ///
    pub fn evm_mut(&mut self) -> &mut EVMData<'ctx> {
        self.evm_data
            .as_mut()
            .expect("The EVM data must have been initialized")
    }
}
