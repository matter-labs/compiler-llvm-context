//!
//! The LLVM generator context.
//!

pub mod address_space;
pub mod argument;
pub mod build;
pub mod code_type;
pub mod evm_data;
pub mod function;
pub mod r#loop;
pub mod optimizer;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use inkwell::types::BasicType;
use inkwell::values::BasicValue;

use crate::dump_flag::DumpFlag;
use crate::Dependency;

use self::address_space::AddressSpace;
use self::build::Build;
use self::code_type::CodeType;
use self::evm_data::EVMData;
use self::function::evm_data::EVMData as FunctionEVMData;
use self::function::intrinsic::Intrinsic as IntrinsicFunction;
use self::function::r#return::Return as FunctionReturn;
use self::function::runtime::Runtime;
use self::function::Function;
use self::optimizer::Optimizer;
use self::r#loop::Loop;

///
/// The LLVM generator context.
///
pub struct Context<'ctx, D>
where
    D: Dependency,
{
    /// The inner LLVM context.
    llvm: &'ctx inkwell::context::Context,
    /// The inner LLVM context builder.
    builder: inkwell::builder::Builder<'ctx>,
    /// The optimizing tools.
    optimizer: Optimizer<'ctx>,
    /// The current module.
    module: inkwell::module::Module<'ctx>,
    /// The current function.
    function: Option<Function<'ctx>>,
    /// The loop context stack.
    loop_stack: Vec<Loop<'ctx>>,

    /// The runtime functions.
    pub runtime: Runtime<'ctx>,
    /// The declared functions.
    pub functions: HashMap<String, Function<'ctx>>,

    /// The current contract code type.
    code_type: Option<CodeType>,
    /// The project dependency manager.
    dependency_manager: Option<Arc<RwLock<D>>>,
    /// Whether to dump the specified IRs.
    dump_flags: Vec<DumpFlag>,

    /// The EVM compiler data.
    evm_data: Option<EVMData<'ctx>>,
}

impl<'ctx, D> Context<'ctx, D>
where
    D: Dependency,
{
    /// The functions hashmap default capacity.
    const FUNCTION_HASHMAP_INITIAL_CAPACITY: usize = 64;

    /// The loop stack default capacity.
    const LOOP_STACK_INITIAL_CAPACITY: usize = 16;

    ///
    /// Initializes a new LLVM context.
    ///
    pub fn new(
        llvm: &'ctx inkwell::context::Context,
        module_name: &str,
        mut optimizer: Optimizer<'ctx>,
        dependency_manager: Option<Arc<RwLock<D>>>,
        dump_flags: Vec<DumpFlag>,
    ) -> Self {
        let module = llvm.create_module(module_name);
        optimizer.set_module(&module);
        let runtime = Runtime::new(llvm, &module);

        Self {
            llvm,
            builder: llvm.create_builder(),
            optimizer,
            module,
            function: None,
            loop_stack: Vec::with_capacity(Self::LOOP_STACK_INITIAL_CAPACITY),

            runtime,
            functions: HashMap::with_capacity(Self::FUNCTION_HASHMAP_INITIAL_CAPACITY),

            code_type: None,
            dependency_manager,
            dump_flags,

            evm_data: None,
        }
    }

    ///
    /// Initializes a new EVM LLVM context.
    ///
    pub fn new_evm(
        llvm: &'ctx inkwell::context::Context,
        module_name: &str,
        optimizer: Optimizer<'ctx>,
        dependency_manager: Option<Arc<RwLock<D>>>,
        dump_flags: Vec<DumpFlag>,
        evm_data: EVMData<'ctx>,
    ) -> Self {
        let mut object = Self::new(llvm, module_name, optimizer, dependency_manager, dump_flags);
        object.evm_data = Some(evm_data);
        object
    }

    ///
    /// Builds the LLVM module, returning the build artifacts.
    ///
    pub fn build(self, contract_path: &str) -> anyhow::Result<Build> {
        if self.dump_flags.contains(&DumpFlag::LLVM) {
            let llvm_code = self.module().print_to_string().to_string();
            eprintln!("Contract `{}` LLVM IR unoptimized:\n", contract_path);
            println!("{}", llvm_code);
        }
        self.verify().map_err(|error| {
            anyhow::anyhow!(
                "The contract `{}` unoptimized LLVM IR verification error: {}",
                contract_path,
                error
            )
        })?;
        let is_optimized = self.optimize();
        if self.dump_flags.contains(&DumpFlag::LLVM) && is_optimized {
            let llvm_code = self.module().print_to_string().to_string();
            eprintln!("Contract `{}` LLVM IR optimized:\n", contract_path);
            println!("{}", llvm_code);
        }
        self.verify().map_err(|error| {
            anyhow::anyhow!(
                "The contract `{}` optimized LLVM IR verification error: {}",
                contract_path,
                error
            )
        })?;

        let buffer = self
            .target_machine()
            .write_to_memory_buffer(self.module(), inkwell::targets::FileType::Assembly)
            .map_err(|error| {
                anyhow::anyhow!(
                    "The contract `{}` assembly generating error: {}",
                    contract_path,
                    error
                )
            })?;

        let assembly_text = String::from_utf8_lossy(buffer.as_slice()).to_string();
        if self.dump_flags.contains(&DumpFlag::Assembly) {
            eprintln!("Contract `{}` assembly:\n", contract_path);
            println!("{}", assembly_text);
        }

        let assembly =
            zkevm_assembly::Assembly::try_from(assembly_text.clone()).map_err(|error| {
                anyhow::anyhow!(
                    "The contract `{}` assembly parsing error: {}",
                    contract_path,
                    error
                )
            })?;

        let bytecode: Vec<u8> = assembly
            .clone()
            .compile_to_bytecode()?
            .into_iter()
            .flatten()
            .collect();

        let hash = crate::hashes::bytecode_hash(bytecode.as_slice()).map_err(|error| {
            anyhow::anyhow!(
                "The contract `{}` bytecode hashing error: {}",
                contract_path,
                error
            )
        })?;

        Ok(Build::new(assembly_text, assembly, bytecode, hash))
    }

    ///
    /// Returns the LLVM IR builder.
    ///
    pub fn builder(&self) -> &inkwell::builder::Builder<'ctx> {
        &self.builder
    }

    ///
    /// Returns the current module reference.
    ///
    pub fn module(&self) -> &inkwell::module::Module<'ctx> {
        &self.module
    }

    ///
    /// Returns the target machine reference.
    ///
    pub fn target_machine(&self) -> &inkwell::targets::TargetMachine {
        self.optimizer.target_machine()
    }

    ///
    /// Sets the current code type.
    ///
    pub fn set_code_type(&mut self, code_type: CodeType) {
        self.code_type = Some(code_type);
    }

    ///
    /// Returns the current code type.
    ///
    pub fn code_type(&self) -> CodeType {
        self.code_type.expect("Always exists")
    }

    ///
    /// Checks whether the specified dump flag is set.
    ///
    pub fn has_dump_flag(&self, dump_flag: DumpFlag) -> bool {
        self.dump_flags.contains(&dump_flag)
    }

    ///
    /// Optimizes the current module.
    ///
    /// Should be only run when the entire module has been translated.
    ///
    /// Only returns `true` if any of the passes modified the function.
    ///
    pub fn optimize(&self) -> bool {
        let mut is_optimized = false;

        for (_, function) in self.functions.iter() {
            is_optimized |= self.optimizer.run_on_function(function.value);
        }
        is_optimized |= self.optimizer.run_on_module(self.module());

        is_optimized
    }

    ///
    /// Verifies the current module.
    ///
    /// # Panics
    /// If verification fails.
    ///
    pub fn verify(&self) -> anyhow::Result<()> {
        self.module()
            .verify()
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    ///
    /// Compiles a contract dependency, if the dependency manager is set.
    ///
    pub fn compile_dependency(&mut self, name: &str) -> anyhow::Result<String> {
        self.dependency_manager
            .to_owned()
            .ok_or_else(|| anyhow::anyhow!("The dependency manager is unset"))
            .and_then(|manager| {
                Dependency::compile(
                    manager,
                    name,
                    self.optimizer.settings().to_owned(),
                    self.dump_flags.clone(),
                )
            })
    }

    ///
    /// Gets a deployed library address.
    ///
    pub fn resolve_library(&self, path: &str) -> anyhow::Result<inkwell::values::IntValue<'ctx>> {
        self.dependency_manager
            .to_owned()
            .ok_or_else(|| anyhow::anyhow!("The dependency manager is unset"))
            .and_then(|manager| {
                let address = manager.read().expect("Sync").resolve_library(path)?;
                Ok(self.field_const_str(address.as_str()))
            })
    }

    ///
    /// Appends a function to the current module.
    ///
    pub fn add_function(
        &mut self,
        name: &str,
        r#type: inkwell::types::FunctionType<'ctx>,
        mut linkage: Option<inkwell::module::Linkage>,
    ) {
        if name.starts_with(Function::ZKSYNC_NEAR_CALL_ABI_PREFIX)
            || name == Function::ZKSYNC_NEAR_CALL_ABI_EXCEPTION_HANDLER
        {
            linkage = Some(inkwell::module::Linkage::External);
        }

        let value = self.module().add_function(name, r#type, linkage);
        for index in 0..value.count_params() {
            if value
                .get_nth_param(index)
                .map(|argument| argument.get_type().is_pointer_type())
                .unwrap_or_default()
            {
                value.set_param_alignment(index, compiler_common::SIZE_FIELD as u32);
            }
        }

        if name.starts_with(Function::ZKSYNC_NEAR_CALL_ABI_PREFIX)
            || name == Function::ZKSYNC_NEAR_CALL_ABI_EXCEPTION_HANDLER
        {
            value.add_attribute(
                inkwell::attributes::AttributeLoc::Function,
                self.llvm
                    .create_enum_attribute(inkwell::LLVMAttributeKindCode::NoInline, 0),
            );
        }

        value.set_personality_function(self.runtime.personality);

        let entry_block = self.llvm.append_basic_block(value, "entry");
        let catch_block = self.llvm.append_basic_block(value, "catch");
        let return_block = self.llvm.append_basic_block(value, "return");

        let function = Function::new(
            name.to_owned(),
            value,
            entry_block,
            catch_block,
            return_block,
            None,
        );
        self.functions.insert(name.to_string(), function.clone());
    }

    ///
    /// Appends a function to the current module.
    ///
    pub fn add_function_evm(
        &mut self,
        name: &str,
        r#type: inkwell::types::FunctionType<'ctx>,
        linkage: Option<inkwell::module::Linkage>,
        evm_data: FunctionEVMData<'ctx>,
    ) {
        self.add_function(name, r#type, linkage);
        self.functions
            .get_mut(name)
            .expect("Always exists")
            .evm_data = Some(evm_data);
    }

    ///
    /// Returns the current function.
    ///
    pub fn function(&self) -> &Function<'ctx> {
        self.function.as_ref().expect("Must be declared before use")
    }

    ///
    /// Returns the current function as a mutable reference.
    ///
    pub fn function_mut(&mut self) -> &mut Function<'ctx> {
        self.function.as_mut().expect("Must be declared before use")
    }

    ///
    /// Sets the current function.
    ///
    /// # Panics
    /// If the function with `name` does not exist.
    ///
    pub fn set_function(&mut self, function: Function<'ctx>) {
        self.function = Some(function);
    }

    ///
    /// Sets the return entity for the current function.
    ///
    pub fn set_function_return(&mut self, r#return: FunctionReturn<'ctx>) {
        let name = self.function().name.clone();

        self.functions
            .get_mut(name.as_str())
            .expect("Always exists")
            .set_return(r#return.clone());
        self.function_mut().set_return(r#return);
    }

    ///
    /// Returns the specified intrinsic function.
    ///
    pub fn get_intrinsic_function(
        &self,
        intrinsic: IntrinsicFunction,
    ) -> inkwell::values::FunctionValue<'ctx> {
        self.module()
            .get_intrinsic_function(intrinsic.name(), intrinsic.argument_types(self).as_slice())
            .unwrap_or_else(|| panic!("Intrinsic function `{}` does not exist", intrinsic.name()))
    }

    ///
    /// Appends a new basic block to the current function.
    ///
    pub fn append_basic_block(&self, name: &str) -> inkwell::basic_block::BasicBlock<'ctx> {
        self.llvm.append_basic_block(self.function().value, name)
    }

    ///
    /// Sets the current basic block.
    ///
    pub fn set_basic_block(&self, block: inkwell::basic_block::BasicBlock<'ctx>) {
        self.builder.position_at_end(block);
    }

    ///
    /// Returns the current basic block.
    ///
    pub fn basic_block(&self) -> inkwell::basic_block::BasicBlock<'ctx> {
        self.builder.get_insert_block().expect("Always exists")
    }

    ///
    /// Pushes a new loop context to the stack.
    ///
    pub fn push_loop(
        &mut self,
        body_block: inkwell::basic_block::BasicBlock<'ctx>,
        continue_block: inkwell::basic_block::BasicBlock<'ctx>,
        join_block: inkwell::basic_block::BasicBlock<'ctx>,
    ) {
        self.loop_stack
            .push(Loop::new(body_block, continue_block, join_block));
    }

    ///
    /// Pops the current loop context from the stack.
    ///
    pub fn pop_loop(&mut self) {
        self.loop_stack.pop();
    }

    ///
    /// Returns the current loop context.
    ///
    pub fn r#loop(&self) -> &Loop<'ctx> {
        self.loop_stack
            .last()
            .expect("The current context is not in a loop")
    }

    ///
    /// Builds a stack allocation instruction.
    ///
    /// Sets the alignment to 256 bits.
    ///
    pub fn build_alloca<T: BasicType<'ctx>>(
        &self,
        r#type: T,
        name: &str,
    ) -> inkwell::values::PointerValue<'ctx> {
        let pointer = self.builder.build_alloca(r#type, name);
        self.basic_block()
            .get_last_instruction()
            .expect("Always exists")
            .set_alignment(compiler_common::SIZE_FIELD as u32)
            .expect("Alignment is valid");
        pointer
    }

    ///
    /// Builds a stack store instruction.
    ///
    /// Sets the alignment to 256 bits for stack and 1 bit for heap, parent, and child.
    ///
    pub fn build_store<V: BasicValue<'ctx>>(
        &self,
        pointer: inkwell::values::PointerValue<'ctx>,
        value: V,
    ) {
        let instruction = self.builder.build_store(pointer, value);

        let alignment = if inkwell::AddressSpace::from(AddressSpace::Stack)
            == pointer.get_type().get_address_space()
        {
            compiler_common::SIZE_FIELD
        } else {
            1
        };

        instruction
            .set_alignment(alignment as u32)
            .expect("Alignment is valid");
    }

    ///
    /// Builds a stack load instruction.
    ///
    /// Sets the alignment to 256 bits for stack and 1 bit for heap, parent, and child.
    ///
    pub fn build_load(
        &self,
        pointer: inkwell::values::PointerValue<'ctx>,
        name: &str,
    ) -> inkwell::values::BasicValueEnum<'ctx> {
        let value = self.builder.build_load(pointer, name);

        let alignment = if inkwell::AddressSpace::from(AddressSpace::Stack)
            == pointer.get_type().get_address_space()
        {
            compiler_common::SIZE_FIELD
        } else {
            1
        };

        self.basic_block()
            .get_last_instruction()
            .expect("Always exists")
            .set_alignment(alignment as u32)
            .expect("Alignment is valid");
        value
    }

    ///
    /// Builds a conditional branch.
    ///
    /// Checks if there are no other terminators in the block.
    ///
    pub fn build_conditional_branch(
        &self,
        comparison: inkwell::values::IntValue<'ctx>,
        then_block: inkwell::basic_block::BasicBlock<'ctx>,
        else_block: inkwell::basic_block::BasicBlock<'ctx>,
    ) {
        if self.basic_block().get_terminator().is_some() {
            return;
        }

        self.builder
            .build_conditional_branch(comparison, then_block, else_block);
    }

    ///
    /// Builds an unconditional branch.
    ///
    /// Checks if there are no other terminators in the block.
    ///
    pub fn build_unconditional_branch(
        &self,
        destination_block: inkwell::basic_block::BasicBlock<'ctx>,
    ) {
        if self.basic_block().get_terminator().is_some() {
            return;
        }

        self.builder.build_unconditional_branch(destination_block);
    }

    ///
    /// Builds a call.
    ///
    pub fn build_call(
        &self,
        function: inkwell::values::FunctionValue<'ctx>,
        args: &[inkwell::values::BasicValueEnum<'ctx>],
        name: &str,
    ) -> Option<inkwell::values::BasicValueEnum<'ctx>> {
        let call_site_value = self.builder.build_call(function, args, name);

        if name == Runtime::FUNCTION_CXA_THROW {
            return call_site_value.try_as_basic_value().left();
        }

        for index in 0..function.count_params() {
            if function
                .get_nth_param(index)
                .map(|argument| argument.get_type().is_pointer_type())
                .unwrap_or_default()
            {
                call_site_value.set_alignment_attribute(
                    inkwell::attributes::AttributeLoc::Param(index),
                    compiler_common::SIZE_FIELD as u32,
                );
            }
        }

        if call_site_value
            .try_as_basic_value()
            .map_left(|value| value.is_pointer_value())
            .left_or_default()
        {
            call_site_value.set_alignment_attribute(
                inkwell::attributes::AttributeLoc::Return,
                compiler_common::SIZE_FIELD as u32,
            );
        }

        call_site_value.try_as_basic_value().left()
    }

    ///
    /// Builds an invoke.
    ///
    /// If there is no bootloader exception handler, the behavior defaults to `build_call`.
    ///
    pub fn build_invoke(
        &self,
        function: inkwell::values::FunctionValue<'ctx>,
        args: &[inkwell::values::BasicValueEnum<'ctx>],
        name: &str,
    ) -> Option<inkwell::values::BasicValueEnum<'ctx>> {
        let join_block = self.append_basic_block("join");

        let call_site_value = self.builder.build_invoke(
            function,
            args,
            join_block,
            self.function().catch_block,
            name,
        );

        for index in 0..function.count_params() {
            if function
                .get_nth_param(index)
                .map(|argument| argument.get_type().is_pointer_type())
                .unwrap_or_default()
            {
                call_site_value.set_alignment_attribute(
                    inkwell::attributes::AttributeLoc::Param(index),
                    compiler_common::SIZE_FIELD as u32,
                );
            }
        }

        if call_site_value
            .try_as_basic_value()
            .map_left(|value| value.is_pointer_value())
            .left_or_default()
        {
            call_site_value.set_alignment_attribute(
                inkwell::attributes::AttributeLoc::Return,
                compiler_common::SIZE_FIELD as u32,
            );
        }

        self.set_basic_block(join_block);
        call_site_value.try_as_basic_value().left()
    }

    ///
    /// Builds a near call ABI invoke.
    ///
    pub fn build_invoke_near_call_abi(
        &self,
        function: inkwell::values::FunctionValue<'ctx>,
        args: Vec<inkwell::values::BasicValueEnum<'ctx>>,
        name: &str,
    ) -> Option<inkwell::values::BasicValueEnum<'ctx>> {
        let success_block = self.append_basic_block("success_block");
        let join_block = self.append_basic_block("join_block");

        let result_pointer = if let Some(r#type) = function.get_type().get_return_type() {
            let pointer = self.build_alloca(r#type, "near_call_return_pointer");
            self.build_store(pointer, r#type.const_zero());
            Some(pointer)
        } else {
            None
        };

        let catch_block = if name.starts_with(Function::ZKSYNC_NEAR_CALL_ABI_PREFIX) {
            if let Some(handler) = self
                .functions
                .get(Function::ZKSYNC_NEAR_CALL_ABI_EXCEPTION_HANDLER)
            {
                let current_block = self.basic_block();
                let near_call_catch_block = self.append_basic_block("near_call_catch_block");

                self.set_basic_block(near_call_catch_block);
                let landing_pad_type = self.structure_type(vec![
                    self.integer_type(compiler_common::BITLENGTH_BYTE)
                        .ptr_type(AddressSpace::Stack.into())
                        .as_basic_type_enum(),
                    self.integer_type(compiler_common::BITLENGTH_X32)
                        .as_basic_type_enum(),
                ]);
                self.builder.build_landing_pad(
                    landing_pad_type,
                    self.runtime.personality,
                    vec![self
                        .integer_type(compiler_common::BITLENGTH_BYTE)
                        .ptr_type(AddressSpace::Stack.into())
                        .const_zero()
                        .as_basic_value_enum()],
                    "near_call_catch_landing",
                );
                self.build_call(handler.value, &[], "near_call_catch_call");
                self.build_unconditional_branch(join_block);

                self.set_basic_block(current_block);
                near_call_catch_block
            } else {
                self.function().catch_block
            }
        } else {
            self.function().catch_block
        };

        let call_site_value = self.builder.build_invoke(
            self.get_intrinsic_function(IntrinsicFunction::NearCall),
            args.as_slice(),
            success_block,
            catch_block,
            name,
        );

        for index in 0..function.count_params() {
            if function
                .get_nth_param(index)
                .map(|argument| argument.get_type().is_pointer_type())
                .unwrap_or_default()
            {
                call_site_value.set_alignment_attribute(
                    inkwell::attributes::AttributeLoc::Param(index),
                    compiler_common::SIZE_FIELD as u32,
                );
            }
        }

        if call_site_value
            .try_as_basic_value()
            .map_left(|value| value.is_pointer_value())
            .left_or_default()
        {
            call_site_value.set_alignment_attribute(
                inkwell::attributes::AttributeLoc::Return,
                compiler_common::SIZE_FIELD as u32,
            );
        }

        self.set_basic_block(success_block);
        if let (Some(pointer), Some(value)) =
            (result_pointer, call_site_value.try_as_basic_value().left())
        {
            self.build_store(pointer, value);
        }
        self.build_unconditional_branch(join_block);

        self.set_basic_block(join_block);
        result_pointer.map(|pointer| self.build_load(pointer, "near_call_result"))
    }

    ///
    /// Builds a memory copy call.
    ///
    /// Sets the alignment to 1 bit for heap, parent, and child.
    ///
    pub fn build_memcpy(
        &self,
        intrinsic: IntrinsicFunction,
        destination: inkwell::values::PointerValue<'ctx>,
        source: inkwell::values::PointerValue<'ctx>,
        size: inkwell::values::IntValue<'ctx>,
        name: &str,
    ) {
        let intrinsic = self.get_intrinsic_function(intrinsic);

        let call_site_value = self.builder.build_call(
            intrinsic,
            &[
                destination.as_basic_value_enum(),
                source.as_basic_value_enum(),
                size.as_basic_value_enum(),
                self.integer_type(compiler_common::BITLENGTH_BOOLEAN)
                    .const_zero()
                    .as_basic_value_enum(),
            ],
            name,
        );

        call_site_value.set_alignment_attribute(inkwell::attributes::AttributeLoc::Param(0), 1);
        call_site_value.set_alignment_attribute(inkwell::attributes::AttributeLoc::Param(1), 1);
    }

    ///
    /// Builds a return.
    ///
    /// Checks if there are no other terminators in the block.
    ///
    pub fn build_return(&self, value: Option<&dyn BasicValue<'ctx>>) {
        if self.basic_block().get_terminator().is_some() {
            return;
        }

        self.builder.build_return(value);
    }

    ///
    /// Builds an unreachable.
    ///
    /// Checks if there are no other terminators in the block.
    ///
    pub fn build_unreachable(&self) {
        if self.basic_block().get_terminator().is_some() {
            return;
        }

        self.builder.build_unreachable();
    }

    ///
    /// Builds an exception catching block sequence.
    ///
    pub fn build_catch_block(&self) {
        self.set_basic_block(self.function().catch_block);
        let landing_pad_type = self.structure_type(vec![
            self.integer_type(compiler_common::BITLENGTH_BYTE)
                .ptr_type(AddressSpace::Stack.into())
                .as_basic_type_enum(),
            self.integer_type(compiler_common::BITLENGTH_X32)
                .as_basic_type_enum(),
        ]);
        self.builder.build_landing_pad(
            landing_pad_type,
            self.runtime.personality,
            vec![self
                .integer_type(compiler_common::BITLENGTH_BYTE)
                .ptr_type(AddressSpace::Stack.into())
                .const_zero()
                .as_basic_value_enum()],
            "landing",
        );
        self.build_call(
            self.runtime.cxa_throw,
            &[self
                .integer_type(compiler_common::BITLENGTH_BYTE)
                .ptr_type(AddressSpace::Stack.into())
                .const_null()
                .as_basic_value_enum(); 3],
            Runtime::FUNCTION_CXA_THROW,
        );

        self.build_unreachable();
    }

    ///
    /// Builds a long contract exit sequence.
    ///
    pub fn build_exit(
        &self,
        return_function: IntrinsicFunction,
        offset: inkwell::values::IntValue<'ctx>,
        length: inkwell::values::IntValue<'ctx>,
    ) {
        let offset = self.builder.build_and(
            offset,
            self.field_const(u64::MAX),
            "contract_exit_offset_truncated",
        );
        let length = self.builder.build_and(
            length,
            self.field_const(u64::MAX),
            "contract_exit_length_truncated",
        );

        let length_shifted = self.builder.build_left_shift(
            length,
            self.field_const(compiler_common::BITLENGTH_X64 as u64),
            "contract_exit_length_shifted",
        );
        let abi_data = self
            .builder
            .build_int_add(length_shifted, offset, "contract_exit_abi_data");

        self.build_call(
            self.get_intrinsic_function(return_function),
            &[abi_data.as_basic_value_enum()],
            format!("contract_exit_{}", return_function.name()).as_str(),
        );
        self.build_unreachable();
    }

    ///
    /// Builds a long contract exit with message sequence.
    ///
    pub fn build_exit_with_message(&self, return_function: IntrinsicFunction, message: &str) {
        let length_shifted = self.builder.build_left_shift(
            self.field_const(compiler_common::SIZE_X64 as u64),
            self.field_const(compiler_common::BITLENGTH_X64 as u64),
            "contract_exit_with_message_length_shifted",
        );
        let abi_data = self.builder.build_int_add(
            length_shifted,
            self.field_const(0),
            "contract_exit_with_message_abi_data",
        );

        let error_hash = crate::hashes::keccak256(message.as_bytes());
        let error_code = self.field_const_str(error_hash.as_str());
        let error_code_shifted = self.builder.build_left_shift(
            error_code,
            self.field_const(
                (compiler_common::BITLENGTH_BYTE
                    * (compiler_common::SIZE_FIELD - compiler_common::SIZE_X32))
                    as u64,
            ),
            "contract_exit_with_message_error_code_shifted",
        );
        let parent_error_code_pointer = self.access_memory(
            self.field_const(0),
            AddressSpace::Heap,
            "contract_exit_with_message_error_code_pointer",
        );
        self.build_store(parent_error_code_pointer, error_code_shifted);

        self.build_call(
            self.get_intrinsic_function(return_function),
            &[abi_data.as_basic_value_enum()],
            format!("contract_exit_with_message_{}", return_function.name()).as_str(),
        );
        self.build_unreachable();
    }

    ///
    /// Reads the ABI data from the specified heap area.
    ///
    pub fn read_abi_data(&self, address_space: AddressSpace) -> inkwell::values::IntValue<'ctx> {
        let (offset_offset, length_offset) = match address_space {
            AddressSpace::Parent => (
                compiler_common::ABI_MEMORY_OFFSET_CALLDATA_OFFSET,
                compiler_common::ABI_MEMORY_OFFSET_CALLDATA_LENGTH,
            ),
            AddressSpace::Child => (
                compiler_common::ABI_MEMORY_OFFSET_RETURN_DATA_OFFSET,
                compiler_common::ABI_MEMORY_OFFSET_RETURN_DATA_LENGTH,
            ),
            address_space => panic!(
                "Address space {:?} cannot be accesses via the ABI data",
                address_space
            ),
        };

        let data_offset_pointer = self.access_memory(
            self.field_const((offset_offset * compiler_common::SIZE_FIELD) as u64),
            AddressSpace::Heap,
            "data_offset_pointer",
        );
        let data_offset = self
            .build_load(data_offset_pointer, "data_offset")
            .into_int_value();

        let data_length_pointer = self.access_memory(
            self.field_const((length_offset * compiler_common::SIZE_FIELD) as u64),
            AddressSpace::Heap,
            "data_length_pointer",
        );
        let data_length = self
            .build_load(data_length_pointer, "data_length")
            .into_int_value();
        let data_length_shifted = self.builder.build_left_shift(
            data_length,
            self.field_const(compiler_common::BITLENGTH_X64 as u64),
            "data_length_shifted",
        );

        self.builder
            .build_int_add(data_offset, data_length_shifted, "data_merged")
    }

    ///
    /// Writes the ABI data to the specified heap area.
    ///
    pub fn write_abi_data(
        &self,
        offset: inkwell::values::IntValue<'ctx>,
        length: inkwell::values::IntValue<'ctx>,
        address_space: AddressSpace,
    ) {
        let (offset_offset, length_offset) = match address_space {
            AddressSpace::Parent => (
                compiler_common::ABI_MEMORY_OFFSET_CALLDATA_OFFSET,
                compiler_common::ABI_MEMORY_OFFSET_CALLDATA_LENGTH,
            ),
            AddressSpace::Child => (
                compiler_common::ABI_MEMORY_OFFSET_RETURN_DATA_OFFSET,
                compiler_common::ABI_MEMORY_OFFSET_RETURN_DATA_LENGTH,
            ),
            address_space => panic!(
                "Address space {:?} cannot be accesses via the ABI data",
                address_space
            ),
        };

        let offset_pointer = self.access_memory(
            self.field_const((offset_offset * compiler_common::SIZE_FIELD) as u64),
            AddressSpace::Heap,
            "offset_pointer",
        );
        self.build_store(offset_pointer, offset);

        let length_pointer = self.access_memory(
            self.field_const((length_offset * compiler_common::SIZE_FIELD) as u64),
            AddressSpace::Heap,
            "length_pointer",
        );
        self.build_store(length_pointer, length);
    }

    ///
    /// Returns a field type constant.
    ///
    pub fn field_const(&self, value: u64) -> inkwell::values::IntValue<'ctx> {
        self.field_type().const_int(value, false)
    }

    ///
    /// Returns a field type constant from a decimal or hexadecimal string.
    ///
    pub fn field_const_str(&self, value: &str) -> inkwell::values::IntValue<'ctx> {
        match value.strip_prefix("0x") {
            Some(hexadecimal) => self.field_const_str_hex(hexadecimal),
            None => self.field_const_str_hex(value),
        }
    }

    ///
    /// Returns a field type constant from a hexadecimal string.
    ///
    pub fn field_const_str_dec(&self, value: &str) -> inkwell::values::IntValue<'ctx> {
        self.field_type()
            .const_int_from_string(value, inkwell::types::StringRadix::Decimal)
            .unwrap_or_else(|| panic!("Invalid string constant `{}`", value))
    }

    ///
    /// Returns a field type constant from a hexadecimal string.
    ///
    pub fn field_const_str_hex(&self, value: &str) -> inkwell::values::IntValue<'ctx> {
        self.field_type()
            .const_int_from_string(
                value.strip_prefix("0x").unwrap_or(value),
                inkwell::types::StringRadix::Hexadecimal,
            )
            .unwrap_or_else(|| panic!("Invalid string constant `{}`", value))
    }

    ///
    /// Returns the void type.
    ///
    pub fn void_type(&self) -> inkwell::types::VoidType<'ctx> {
        self.llvm.void_type()
    }

    ///
    /// Returns the integer type of the specified bitlength.
    ///
    pub fn integer_type(&self, bitlength: usize) -> inkwell::types::IntType<'ctx> {
        self.llvm.custom_width_int_type(bitlength as u32)
    }

    ///
    /// Returns the default field type.
    ///
    pub fn field_type(&self) -> inkwell::types::IntType<'ctx> {
        self.llvm
            .custom_width_int_type(compiler_common::BITLENGTH_FIELD as u32)
    }

    ///
    /// Returns the structure type with specified fields.
    ///
    pub fn structure_type(
        &self,
        field_types: Vec<inkwell::types::BasicTypeEnum<'ctx>>,
    ) -> inkwell::types::StructType<'ctx> {
        self.llvm.struct_type(field_types.as_slice(), false)
    }

    ///
    /// Returns the function type for the specified parameters.
    ///
    pub fn function_type(
        &self,
        return_values_length: usize,
        mut argument_types: Vec<inkwell::types::BasicTypeEnum<'ctx>>,
    ) -> inkwell::types::FunctionType<'ctx> {
        match return_values_length {
            0 => self
                .llvm
                .void_type()
                .fn_type(argument_types.as_slice(), false),
            1 => self.field_type().fn_type(argument_types.as_slice(), false),
            length => {
                let return_types: Vec<_> = vec![self.field_type().as_basic_type_enum(); length];
                let return_type = self
                    .llvm
                    .struct_type(return_types.as_slice(), false)
                    .ptr_type(AddressSpace::Stack.into());
                argument_types.insert(0, return_type.as_basic_type_enum());
                return_type.fn_type(argument_types.as_slice(), false)
            }
        }
    }

    ///
    /// Returns the memory pointer to `address_space` at `offset` bytes.
    ///
    pub fn access_memory(
        &self,
        offset: inkwell::values::IntValue<'ctx>,
        address_space: AddressSpace,
        name: &str,
    ) -> inkwell::values::PointerValue<'ctx> {
        self.builder.build_int_to_ptr(
            offset,
            self.field_type().ptr_type(address_space.into()),
            name,
        )
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
