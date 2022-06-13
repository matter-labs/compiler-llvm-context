//!
//! The LLVM context library.
//!

pub(crate) mod context;
pub(crate) mod dump_flag;
pub(crate) mod evm;
pub(crate) mod hashes;

pub use self::context::address_space::AddressSpace;
pub use self::context::argument::Argument;
pub use self::context::attribute::Attribute;
pub use self::context::build::Build;
pub use self::context::code_type::CodeType;
pub use self::context::evm_data::EVMData as ContextEVMData;
pub use self::context::function::block::evm_data::EVMData as FunctionBlockEVMData;
pub use self::context::function::block::key::Key as FunctionBlockKey;
pub use self::context::function::block::Block as FunctionBlock;
pub use self::context::function::deploy_code::DeployCode as DeployCodeFunction;
pub use self::context::function::evm_data::EVMData as FunctionEVMData;
pub use self::context::function::intrinsic::Intrinsic as IntrinsicFunction;
pub use self::context::function::r#return::Return as FunctionReturn;
pub use self::context::function::runtime::Runtime;
pub use self::context::function::runtime_code::RuntimeCode as RuntimeCodeFunction;
pub use self::context::function::Function;
pub use self::context::optimizer::settings::size_level::SizeLevel as OptimizerSettingsSizeLevel;
pub use self::context::optimizer::settings::Settings as OptimizerSettings;
pub use self::context::optimizer::Optimizer;
pub use self::context::r#loop::Loop;
pub use self::context::Context;
pub use self::dump_flag::DumpFlag;
pub use self::evm::arithmetic;
pub use self::evm::bitwise;
pub use self::evm::calldata;
pub use self::evm::comparison;
pub use self::evm::contract;
pub use self::evm::create;
pub use self::evm::ether_gas;
pub use self::evm::event;
pub use self::evm::ext_code;
pub use self::evm::hash;
pub use self::evm::immutable;
pub use self::evm::math;
pub use self::evm::memory;
pub use self::evm::r#return;
pub use self::evm::return_data;
pub use self::evm::storage;
pub use self::evm::verbatim;
pub use self::hashes::bytecode_hash;
pub use self::hashes::keccak256;

use std::sync::Arc;
use std::sync::RwLock;

///
/// Initializes the zkEVM target machine.
///
pub fn initialize_target() {
    inkwell::targets::Target::initialize_syncvm(&inkwell::targets::InitializationConfig::default());
}

///
/// Implemented by items which are translated into LLVM IR.
///
#[allow(clippy::upper_case_acronyms)]
pub trait WriteLLVM<D>
where
    D: Dependency,
{
    ///
    /// Declares the entity in the LLVM IR.
    /// Is usually performed in order to use the item before defining it.
    ///
    fn declare(&mut self, _context: &mut Context<D>) -> anyhow::Result<()> {
        Ok(())
    }

    ///
    /// Translates the entity into LLVM IR.
    ///
    fn into_llvm(self, context: &mut Context<D>) -> anyhow::Result<()>;
}

///
/// The dummy LLVM writable entity.
///
#[derive(Debug, Default)]
pub struct DummyLLVMWritable {}

impl<D> WriteLLVM<D> for DummyLLVMWritable
where
    D: Dependency,
{
    fn into_llvm(self, _context: &mut Context<D>) -> anyhow::Result<()> {
        Ok(())
    }
}

///
/// Implemented by items managing project dependencies.
///
pub trait Dependency {
    ///
    /// Compiles a project dependency.
    ///
    fn compile(
        object: Arc<RwLock<Self>>,
        path: &str,
        optimizer_settings: OptimizerSettings,
        dump_flags: Vec<DumpFlag>,
    ) -> anyhow::Result<String>;

    ///
    /// Resolves a full contract path.
    ///
    fn resolve_path(&self, identifier: &str) -> anyhow::Result<String>;

    ///
    /// Resolves a library address.
    ///
    fn resolve_library(&self, path: &str) -> anyhow::Result<String>;
}
