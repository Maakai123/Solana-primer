 Rust smart contract security guide in Solana
Preface
In the current blockchain ecosystem, Solana is known for its high performance and scalability. As a rapidly growing blockchain platform, Solana solves many challenges faced by traditional blockchains, such as transaction speed and scalability issues, through its unique architecture and innovative consensus mechanism. Solana’s high throughput and low latency make it ideal for decentralized finance (DeFi), NFT markets, and many other fields.

With its excellent security and performance advantages, the Rust language has become the language of choice for Solana blockchain smart contract development. Rust’s memory safety features and zero-cost abstractions give it significant advantages when developing efficient and secure blockchain applications. The strict compiler checks and concurrency provided by Rust enable developers to write efficient and safe code that avoids many common programming mistakes.

In this article, we will explore in detail the common security issues of developing smart contracts in the Solana blockchain using the Rust language. Through analysis of various vulnerabilities and security suggestions, we help developers improve the security of Solana smart contracts and ensure their reliability in decentralized applications.

Rust safety
1. Arithmetic problems
Integer overflow/underflow: Overflow occurs when the input value exceeds the bounds of the integer type. This can lead to data errors and potential security vulnerabilities.
Large type conversion, small type overflow: When converting large type data to small type, if the value exceeds the range of the target type, overflow will occur, causing data corruption.
divide by zero: Performing a division operation when the denominator is zero will cause a runtime error. You need to check whether the denominator is zero before the division operation.
Decimal calculations must be precise when making rounding decisions: In decimal calculations, rounding errors can lead to inaccurate calculation results, especially in financial calculations and other decimal operations that require precision.
Multiply first then divide: In some cases, multiplying before dividing can avoid overflow and loss of precision.
Integer overflow caused by unvalidated data: When input data is used directly without verification, it may cause integer overflow and bring security risks.
1.1 Integer overflow
Vulnerability example
Integer overflow and underflow occur when trying to store a value that exceeds the maximum or minimum value of the data type. Overflow occurs if the sum of a and b exceeds the maximum value of u32 (4,294,967,295). This can lead to unexpected behavior and potential security vulnerabilities.

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let a = u32::from_le_bytes(instruction_data[0..4].try_into().unwrap());
    let b = u32::from_le_bytes(instruction_data[4..8].try_into().unwrap());

    let result = add(a, b);

    msg!("Result of addition: {}", result);

    Ok(())
}

// Vulnerability example: unchecked integer overflow
fn add(a: u32, b: u32) -> u32 {
    a + b // If the sum of a and b exceeds the maximum value of u32, overflow will occur
}
Security advice
Use Rust built-in checking functions to avoid integer overflows. For example, use the checked_add method.

fn add(a: u32, b: u32) -> Result<u32, &'static str> {
    a.checked_add(b).ok_or("Integer overflow detected")
}
1.2 Rounding errors
Vulnerability examples
Rounding errors can result in loss of precision, especially in financial calculations where decimal calculations need to be handled precisely. For example, multiplying $12.345 by 100 and then rounding to two decimal places will result in inaccurate results.

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 12 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let price = f64::from_bits(u64::from_le_bytes(instruction_data[0..8].try_into().unwrap()));
    let quantity = u32::from_le_bytes(instruction_data[8..12].try_into().unwrap());

    let total = calculate_total(price, quantity);

    msg!("Total amount: {}", total);

    Ok(())
}

//Example of vulnerability: rounding error
fn calculate_total(price: f64, quantity: u32) -> f64 {
    let total = price * quantity as f64;
    (total * 100.0).round() / 100.0 // Rounding to two decimal places, which may result in loss of accuracy
}
Security advice
Use fixed-point libraries or integer arithmetic to represent monetary amounts.
When floating point operations are required, minimize the number of rounding operations.
// Safe example: using fixed-point arithmetic
fn calculate_total(price: u64, quantity: u32) -> Result<u64, &'static str> {
    // Define a fixed-point ratio, for example, 1e2 means keeping two decimal places
    let scale = 100u64;
    let scaled_price = price.checked_mul(scale).ok_or("Multiplication overflow")?;
    let total = scaled_price.checked_mul(quantity as u64).ok_or("Multiplication overflow")?;
    Ok(total)
}
2. Memory and stack issues
stack overflow: A stack overflow occurs when a program consumes more memory than is available for the call stack. This usually happens in recursive implementations of functions, causing the program to crash.
Not enough storage: When there is not enough memory allocated for the program to use, an OOM (Out of Memory) error occurs. It can lead to a Denial of Service (DoS), which can happen if the length of the buffer is not checked.
Invalid memory access: Refers to accessing unallocated or released memory, which may lead to undefined behavior or program crash.
null pointer dereference: Refers to accessing a null pointer, which may cause the program to crash.
Use uninitialized memory: Refers to using uninitialized variables or memory, which may lead to undefined behavior or program crash.
buffer overflow: Refers to reading and writing memory outside the buffer boundary, which may cause data corruption or program crash.
Unvalidated data byte limit causes index out of bounds: Refers to the fact that the input data is not verified, causing the index to access memory out of bounds.
2.1 Stack overflow
Vulnerability examples
Recursive calls may cause stack overflow.

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 4 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let n = u32::from_le_bytes(instruction_data[0..4].try_into().unwrap());

    recursive_function(n);

    Ok(())
}

// Vulnerability example: recursive call, may cause stack overflow
fn recursive_function(n: u32) {
    msg!("Recursion depth: {}", n);
    if n > 0 {
        recursive_function(n - 1); // Unlimited recursion, may cause stack overflow
    }
}
Security advice
Limit recursion depth or use an iterative approach.

//Safe example: use iteration method to avoid stack overflow
fn iterative_function(n: u32) {
    let mut i = n;
    while i > 0 {
        msg!("Iteration step: {}", i);
        i -= 1;
    }
}
2.2 Out of memory (OOM)
Vulnerability examples
Attempts to allocate large amounts of memory, may cause OOM

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let size = usize::from_le_bytes(instruction_data[0..8].try_into().unwrap());

    allocate_large_vector(size);

    Ok(())
}

// Vulnerability example: Try to allocate a large amount of memory, which may cause OOM
fn allocate_large_vector(size: usize) {
    let _large_vec = vec![0u8; size]; // The size is not checked, which may cause OOM
}
Security advice
Check memory allocations and limit allocation sizes.

// Safe example: Check memory allocation and limit allocation size
fn allocate_large_vector(size: usize) -> Result<Vec<u8>, &'static str> {
    const MAX_SIZE: usize = 1024 * 1024; // 1 MB limit
    if size > MAX_SIZE {
        return Err("Requested size exceeds limit");
    }
    Ok(vec![0u8; size])
}
3. Parameter verification problem
Function parameters are not strictly verified: Failure to strictly verify function parameters may lead to program freezes or logic errors. For example, input parameters are outside the expected range, resulting in array out-of-bounds or invalid operations.
Vulnerability examples
In the code below, the function parameters are not strictly verified, which may lead to array out-of-bounds or other logic errors.

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let operation = instruction_data[0];
    match operation {
        0 => {
            //Example operation, processing data
            let result = unsafe_process_data(instruction_data);
            if let Err(e) = result {
                msg!("Error processing data: {}", e);
                return Err(ProgramError::InvalidInstructionData);
            }
            Ok(())
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// Vulnerability example: Failure to verify whether the index is within the range may lead to out-of-bounds access
fn unsafe_process_data(data: &[u8]) -> Result<u8, &'static str> {
    if data.len() < 9 {
        return Err("Insufficient data length");
    }

    // Get the index and perform data processing
    let index = usize::from_le_bytes(data[1..9].try_into().unwrap());
    let value = data[index]; // Does not check whether the index is within the range, which may lead to out-of-bounds access

    msg!("Processing data at index {}: {}", index, value);
    Ok(value)
}
Security advice
Strictly validate all function parameters to ensure they are within expected ranges.

4.Initialization problem
Initialize any number of times: Arbitrarily multiple initializations refers to allowing multiple initialization operations without appropriate controls and checks. This will cause the state of the system or contract to be repeatedly reset or maliciously tampered with, causing security issues and logic errors.
Preemptive initialization: Preemptive initialization means that a malicious user or attacker completes the initialization operation before the expected legitimate initialization, thereby gaining control of the system or affecting system behavior. This usually happens without proper permission verification mechanism.
4.1 Initialize any number of times
Vulnerability examples
In the code below, the contract allows any user to perform multiple initialization operations.

struct Contract {
    owner: Option<Address>,
}

impl Contract {
    pub fn new() -> Self {
        Self { owner: None }
    }

    pub fn initialize(&mut self, owner: Address) {
        self.owner = Some(owner);
    }
}
Security advice
Add an initialization check to ensure that initialization can only be performed once and only if it is not initialized yet.

struct Contract {
    owner: Option<Address>,
    is_initialized: bool,
}

impl Contract {
    pub fn new() -> Self {
        Self { owner: None, is_initialized: false }
    }

    pub fn initialize(&mut self, owner: Address) -> Result<(), &'static str> {
        if self.is_initialized {
            return Err("Already initialized");
        }
        self.owner = Some(owner);
        self.is_initialized = true;
        Ok(())
    }
}
5.DoS
Not verifying whether the NFT owner is actually the transaction signer: During an NFT transaction, if the NFT owner is not verified as a signer of the transaction, an anonymous attacker may cause a DoS (denial of service) attack on the program by canceling all sell orders. This will prevent legitimate users from conducting transactions normally.
Submitting false information causes program DoS: If the system does not strictly verify the submitted information, malicious users can submit false information, causing the program to enter an abnormal state or crash, thereby implementing a DoS attack and affecting the normal operation of the system.
5.1 Not verifying whether the NFT owner is the transaction signer
Vulnerability examples
In the code below, the NFT owner is not verified as a transaction signer, allowing an attacker to cancel all sell orders.

struct NftContract {
    owner: Address,
}

impl NftContract {
    pub fn cancel_order(&mut self, nft_id: u64) {
        // Assume orders is a hash map that stores all orders
        self.orders.remove(&nft_id);
    }
}
Security advice
Verify that the NFT owner is the transaction signer before processing the order.

struct NftContract {
    owner: Address,
}

impl NftContract {
    pub fn cancel_order(&mut self, nft_id: u64, caller: Address) -> Result<(), &'static str> {
        if self.owner_of(nft_id) != caller {
            return Err("Caller is not the owner of the NFT");
        }
        self.orders.remove(&nft_id);
        Ok(())
    }

    fn owner_of(&self, nft_id: u64) -> Address {
        // Return the owner address corresponding to nft_id
    }
}
5.2 Submitting false information leads to program DoS
Vulnerability examples
In the code below, the submitted information is not strictly verified, and malicious users can submit false information to cause the program to crash.

struct Platform {
    data: Vec<String>,
}

impl Platform {
    pub fn submit_info(&mut self, info: String) {
        self.data.push(info);
    }
}
Security advice
Submitted information is rigorously verified to ensure it conforms to expected format and content.

struct Platform {
    data: Vec<String>,
}

impl Platform {
    pub fn submit_info(&mut self, info: String) -> Result<(), &'static str> {
        if !self.validate_info(&info) {
            return Err("Invalid information submitted");
        }
        self.data.push(info);
        Ok(())
    }

    fn validate_info(&self, info: &str) -> bool {
        // Implement information verification logic, such as checking length, format, etc.
        info.len() > 0 && info.len() <= 100 // For example, the message length must be between 1 and 100
    }
}
6. Front-running problem
Front-Running: The attacker monitors unconfirmed transactions on the network and sends a transaction with a higher priority (usually paying a higher fee) before the legitimate user’s transaction is confirmed, thus causing the legitimate user’s transaction to be delayed. Or simply can’t handle it. Front-running transactions can cause users to suffer financial losses, especially in decentralized finance (DeFi) platforms or decentralized exchanges (DEX), and attackers can obtain excess profits in this way.
Vulnerability examples
In the code below, the transaction is not properly protected, allowing an attacker to pre-empt the transaction by increasing the fee.

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    program_pack::{IsInitialized, Pack, Sealed},
    program::{invoke, invoke_signed},
    sysvar::{net::Rent, Sysvar},
};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Order {
    pub user: Pubkey,
    pub amount: u64,
    pub price: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Dex {
    pub orders: Vec<Order>,
}

impl Dex {
    pub fn place_order(&mut self, order: Order) {
        self.orders.push(order);
    }
}

entrypoint!(process_instruction);
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Deserialize instruction data to get order details
    let order: Order = Order::unpack_from_slice(instruction_data)?;
    let mut dex = Dex::default();

    // Place the order
    dex.place_order(order);

    msg!("Order placed: {:?}", dex.orders);

    Ok(())
}
Use encrypted submission (Commit-Reveal Scheme): Using an encrypted submit and reveal scheme, users first submit encrypted order information, and only the actual content is disclosed during the reveal phase, thus preventing front-running.
Add delayed transactions: Introduce random delays to prevent attackers from determining the order of transactions.
Batch transactions: Package multiple transactions to reduce the possibility of attackers predicting the order of transactions.
7. Call unknown code
Security advice
Calling unverified code: Calling unverified code in smart contracts may lead to unexpected behavior or security vulnerabilities. Unverified code may contain malicious logic or security vulnerabilities, leading to system attacks or data tampering.
Calling unreviewed code: Calling unvetted code may pose a security risk. Unreviewed code may contain undiscovered vulnerabilities, causing system instability or vulnerability to attacks.
7.1 Calling unverified code
Vulnerability examples
In the code below, the contract calls an unverified external contract, which may lead to unexpected security issues.

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::Instruction,
    program::invoke,
    pubkey::Pubkey,
    program_error::ProgramError,
};

fn call_external_contract(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    invoke(
        &Instruction {
            program_id: *program_id,
            accounts: accounts.to_vec(),
            data: instruction_data.to_vec(),
        },
        accounts,
    )
}

//Contract call example
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExampleContract;

impl ExampleContract {
    pub fn process(&self, program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
        // Call external contract
        call_external_contract(program_id, accounts, instruction_data)
    }
}
Security advice
Before calling an external contract, verify its origin and security to ensure it behaves as expected.

8. Different dependency versions lead to security risks
Different dependency versions lead to security risks: Different versions of dependencies may contain different functionality, interfaces, and security vulnerabilities. If a project uses incompatible or security-problematic versions of dependencies, it may cause the entire project to become less secure or cause unexpected errors.
Dependencies out of date: Using outdated dependencies may not get the latest security patches and updates, exposing your project to known security vulnerabilities.
Using vulnerable dependencies: Using dependencies with known vulnerabilities may directly expose the project to these vulnerabilities, resulting in potential security risks.
8.1 Security risks caused by different dependency versions
Vulnerability examples
In the code below, different versions of dependencies may cause security risks. For example, a critical security vulnerability exists in a certain version of a dependency.

# Cargo.toml
[package]
name = "example_contract"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.130" # A specific version of the dependency is used here
Security advice
Try to use the latest version of your dependencies and specify the version range in Cargo.toml. Additionally, tools are available to check the security of dependencies.

# Cargo.toml
[package]
name = "example_contract"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0" # Use the version range to indicate compatibility with the latest version of the `1.0.x` series
9. Account access control, account ownership and permissions
Unauthorized access: Unauthorized access is the act of accessing a resource or performing an operation without passing appropriate permission checks. Attackers may exploit vulnerabilities to bypass permission checks and obtain or tamper with data.
Permissions usage error: Incorrect permission usage means using the wrong permission level when performing certain operations. For example, a regular user can perform actions that only administrators can perform, which can lead to security risks.
Account manipulation vulnerabilities: Attackers perform unauthorized operations by manipulating account information. For example, by tampering with the account address in a transaction, an attacker can transfer funds to his or her own account.
Check account ownership: Make sure the transaction or operation was initiated by the actual owner of the account. If ownership checks are not performed, an attacker could impersonate a legitimate user to perform malicious operations.
Whether the transaction was signed by the appropriate account: Make sure the transaction is signed by a legitimate account. If signature verification is not performed, attackers may forge transactions, resulting in asset theft or data tampering.
9.1 Unauthorized access
Vulnerability examples
use solana_program::pubkey::Pubkey;

struct Contract {
    admin: Pubkey,
}

impl Contract {
    pub fn restricted_action(&self, caller: &Pubkey) {
        // No permission check is performed
        self.perform_action();
    }

    fn perform_action(&self) {
        //Perform certain restricted operations
        println!("Performing a restricted action.");
    }
}

fn main() {
    let admin = Pubkey::new_unique();
    let user = Pubkey::new_unique();
    let contract = Contract { admin };

    // The user attempts to invoke a restricted operation
    contract.restricted_action(&user); // Unauthorized access
}
Security advice
Perform permission checks before performing restricted operations.

9.2 Vulnerabilities in account manipulation
Vulnerability examples
use solana_program::pubkey::Pubkey;
use std::collections::HashMap;

struct Contract {
    balances: HashMap<Pubkey, u64>,
}

impl Contract {
    pub fn transfer(&mut self, from: Pubkey, to: Pubkey, amount: u64) {
        // Did not check whether the account is the legal owner or whether the balance is sufficient
        self.balances.insert(to, amount);
    }
}

fn main() {
    let mut contract = Contract {
        balances: HashMap::new(),
    };

    let user1 = Pubkey::new_unique();
    let user2 = Pubkey::new_unique();

    contract.balances.insert(user1, 100);

    //Illegal transfer, account balance and ownership not checked
    contract.transfer(user1, user2, 50);

    println!("User1 balance: {}", contract.balances.get(&user1).unwrap_or(&0));
    println!("User2 balance: {}", contract.balances.get(&user2).unwrap_or(&0));
}
Security advice
Verify the legitimacy of the account before transferring funds, ensuring that the account balance is sufficient and the account owner authorizes it.

use solana_program::pubkey::Pubkey;
use std::collections::HashMap;

struct Contract {
    balances: HashMap<Pubkey, u64>,
}

impl Contract {
    pub fn transfer(&mut self, from: Pubkey, to: Pubkey, amount: u64) -> Result<(), &'static str> {
        // Check whether the account exists and whether the balance is sufficient
        let from_balance = self.balances.get(&from).ok_or("Account not found")?;
        if *from_balance < amount {
            return Err("Insufficient balance");
        }

        //Perform transfer operation
        *self.balances.get_mut(&from).unwrap() -= amount;
        *self.balances.entry(to).or_insert(0) += amount;

        Ok(())
    }
}

fn main() {
    let mut contract = Contract {
        balances: HashMap::new(),
    };

    let user1 = Pubkey::new_unique();
    let user2 = Pubkey::new_unique();

    contract.balances.insert(user1, 100);

    // Attempt a legal transfer
    match contract.transfer(user1, user2, 50) {
        Ok(_) => println!("Transfer successful."),
        Err(e) => println!("Transfer failed: {}", e),
    }

    println!("User1 balance: {}", contract.balances.get(&user1).unwrap_or(&0));
    println!("User2 balance: {}", contract.balances.get(&user2).unwrap_or(&0));

    // Attempt to transfer illegally and exceed the balance
    match contract.transfer(user1, user2, 100) {
        Ok(_) => println!("Transfer successful."),
        Err(e) => println!("Transfer failed: {}", e),
    }

    println!("User1 balance: {}", contract.balances.get(&user1).unwrap_or(&0));
    println!("User2 balance: {}", contract.balances.get(&user2).unwrap_or(&0));
}
10. Fund management issues
Funds are locked in the contract: When there is a flaw in the contract design that causes funds to be transferred in but unable to be transferred out, the funds will be permanently locked in the contract. This problem is often seen in error handling in smart contracts or in the absence of withdrawal functionality.
Tokens not destroyed properly: Failure to properly destroy tokens after unstaking or certain specific operations will result in the total amount of tokens in the contract being inaccurate, which may lead to economic risks or inconsistencies.
Improper handling after staking pool reduction: After the pledge pool reduction operation, the funds of all users are not adjusted accordingly, which may result in some users being unable to withdraw funds or having inaccurate balances.
10.1 Funds are locked in the contract
Vulnerability examples
struct Contract {
    balances: HashMap<Pubkey, u64>,
}

impl Contract {
    pub fn deposit(&mut self, user: Pubkey, amount: u64) {
        let balance = self.balances.entry(user).or_insert(0);
        *balance += amount;
    }

    pub fn withdraw(&self, user: Pubkey, amount: u64) {
        // Lack of withdrawal logic, resulting in funds being unable to be withdrawn
    }
}
Security advice
Make sure there is a complete fund transfer function in the contract and carry out appropriate permission checks.

impl Contract {
    pub fn withdraw(&mut self, user: Pubkey, amount: u64) -> Result<(), &'static str> {
        let balance = self.balances.get_mut(&user).ok_or("Account not found")?;
        if *balance < amount {
            return Err("Insufficient balance");
        }
        *balance -= amount;
        // Transfer logic, transfer funds to user address
        Ok(())
    }
}
10.2 Tokens not destroyed properly
Vulnerability examples
struct Contract {
    total_supply: u64,
    balances: HashMap<Pubkey, u64>,
}

impl Contract {
    pub fn unstakes(&mut self, user: Pubkey, amount: u64) {
        let balance = self.balances.get_mut(&user).unwrap();
        *balance -= amount;
        // The total supply is not updated, resulting in the token not being destroyed
    }
}
Security advice
Ensure the total supply is updated correctly when unstaking or burning tokens.

impl Contract {
    pub fn unstakes(&mut self, user: Pubkey, amount: u64) -> Result<(), &'static str> {
        let balance = self.balances.get_mut(&user).ok_or("Account not found")?;
        if *balance < amount {
            return Err("Insufficient balance");
        }
        *balance -= amount;
        self.total_supply -= amount;
        Ok(())
    }
}
11. The document description does not match the actual contract code
Document description and code function implementation do not match: This mismatch can lead to user misunderstanding of contract behavior, potentially leading to incorrect use or security vulnerabilities.
Vulnerability examples
The following code example demonstrates a potential inconsistency between the documentation description and the code implementation:

Document description

/// Transfers `amount` tokens from the caller to `recipient`.
///
/// # Parameters
/// - `recipient`: The address of the recipient.
/// - `amount`: The number of tokens to transfer.
///
/// # Returns
/// - `Result<()>`: Returns an Ok result on success, or an Err result if an error occurs.
pub fn transfer(&self, recipient: Pubkey, amount: u64) -> Result<()> {
    // Implementation
}
Actual code:

use solana_program::pubkey::Pubkey;
use std::collections::HashMap;

struct Contract {
    balances: HashMap<Pubkey, u64>,
}

impl Contract {
    /// Transfers `amount` tokens from `sender` to `recipient`.
    ///
    /// # Parameters
    /// - `sender`: The address of the sender.
    /// - `recipient`: The address of the recipient.
    /// - `amount`: The number of tokens to transfer.
    ///
    /// # Returns
    /// - `Result<()>`: Returns an Ok result on success, or an Err result if an error occurs.
    pub fn transfer(&self, sender: Pubkey, recipient: Pubkey, amount: u64) -> Result<(), &'static str> {
        let sender_balance = self.balances.get_mut(&sender).ok_or("Sender not found")?;
        if *sender_balance < amount {
            return Err("Insufficient balance");
        }
        *sender_balance -= amount;
        let recipient_balance = self.balances.entry(recipient).or_insert(0);
        *recipient_balance += amount;
        Ok(())
    }
}

fn main() {
    let mut contract = Contract {
        balances: HashMap::new(),
    };

    let user1 = Pubkey::new_unique();
    let user2 = Pubkey::new_unique();

    contract.balances.insert(user1, 100);

    // Attempt a legal transfer
    match contract.transfer(user1, user2, 50) {
        Ok(_) => println!("Transfer successful."),
        Err(e) => println!("Transfer failed: {}", e),
    }

    println!("User1 balance: {}", contract.balances.get(&user1).unwrap_or(&0));
    println!("User2 balance: {}", contract.balances.get(&user2).unwrap_or(&0));

    // Attempt to transfer illegally and exceed the balance
    match contract.transfer(user1, user2, 100) {
        Ok(_) => println!("Transfer successful."),
        Err(e) => println!("Transfer failed: {}", e),
    }

    println!("User1 balance: {}", contract.balances.get(&user1).unwrap_or(&0));
    println!("User2 balance: {}", contract.balances.get(&user2).unwrap_or(&0));
}
In this example, there is a potential inconsistency between the documentation description and the code implementation that could cause a developer or user to make an error when calling the method.

Security advice
Keep documents in sync: Whenever the code changes, relevant documents are updated in a timely manner to ensure that the documents accurately reflect the code functions.
Use automatic document generation tools: Use Rust’s documentation generation tools, such as rustdoc, to ensure that function signatures and parameter descriptions are automatically generated, reducing manual errors.
code review: During the code review process, not only the code logic should be checked, but also the documentation description should be checked for accuracy and completeness.
test documentation: Write test cases to verify whether the sample code in the document is correct and ensure that the document description is consistent with the actual behavior.
12. Cross-contract call depth
Cross-contract call depth: In Solana, smart contracts can call methods of other smart contracts, which is called cross-program invocation (CPI). This mechanism allows developers to create complex processes through interactions between different contracts. For example, a client can execute a transaction that modifies not just one account, but two accounts in the same chain owned by different programs. However, the CPI depth limit in Solana is 4, which means that one smart contract can only recursively call other smart contracts a maximum of 4 times. If this depth limit is exceeded, the program will fail. This limit is to prevent resource exhaustion caused by infinite recursive calls. Although the Solana documentation mentions that this limit may change in the future, current development must consider this limit and avoid excessively deep recursive calls or complex cross-contract interactions.
Vulnerability examples
The following code shows an example of cross-contract call depth exceeding the limit:

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
    program::invoke,
};

entrypoint!(process_instruction);

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let target_program = next_account_info(account_info_iter)?;

    // first call
    invoke(
        &create_instruction(program_id, target_program.key),
        accounts,
    )?;

    // second call
    invoke(
        &create_instruction(program_id, target_program.key),
        accounts,
    )?;

    // Third call
    invoke(
        &create_instruction(program_id, target_program.key),
        accounts,
    )?;

    // fourth call
    invoke(
        &create_instruction(program_id, target_program.key),
        accounts,
    )?;

    //The fifth call, depth limit exceeded
    invoke(
        &create_instruction(program_id, target_program.key),
        accounts,
    )?;

    Ok(())
}

fn create_instruction(program_id: &Pubkey, target_program: &Pubkey) -> solana_program::instruction::Instruction {
    solana_program::instruction::Instruction {
        program_id: *program_id,
        accounts: vec![],
        data: thing![],
    }
}
In this example, the fifth call to invoke would exceed Solana’s CPI depth limit, causing the program to fail.

Security advice
Reduce the depth of cross-contract calls:Avoid unnecessary cross-contract calls.
Check call depth:When writing code, make sure that the call depth does not exceed the limit.
Optimize contract logic:Optimize the logic in the contract and reduce the number of recursive calls.
13. Exceeding the calculation unit limit
In the Solana blockchain, the execution of smart contracts requires the consumption of Computation Units (CU). Currently, Solana places a cap on CU consumption for a single transaction, typically 48 million CUs. This is similar to the gas limit in Ethereum. Transactions exceeding this limit will fail, rendering the contract unexecutable. This restriction is mainly to prevent a single transaction from excessively consuming network resources and ensure the stability and efficiency of the network.

Compute unit limit is 48 million CU: The complexity of contract execution is directly related to the required CU consumption. If the contract logic is complex and not optimized, it may cause CU consumption to exceed the limit and the transaction to fail.
Complex logic is not simplified and requires a large number of CUs: The use of complex algorithms or data structures in the contract may cause excessive CU consumption. Logic that is not simplified or optimized will increase CU usage and increase the risk of transaction failure.
Vulnerability examples
The following sample code shows an example of excessive compute unit consumption:

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
    program_error::ProgramError,
    msg,
};

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let mut total = 0;
   
    //Perform complex calculations, which may cause excessive CU consumption
    msg!("Starting complex computation...");
    for i in 0..100000000 {
        total += i;
        if i % 10000000 == 0 {
            msg!("Processed {} iterations", i);
        }
    }
   
    if total > 1000000000 {
        return Err(ProgramError::InvalidInstructionData);
    }

    msg!("Complex computation completed with total: {}", total);
    Ok(())
}
In this example, the loop iterates 100 million times. This complex calculation will cause the CU consumption to increase rapidly, which may exceed the 48 million CU limit, causing the transaction to fail.

Security advice
Optimize calculation logic：Avoid unnecessary loops and recursive operations.
Break down complex logic：Split complex logic into multiple independent transaction executions to avoid excessive CU consumption of a single transaction.
Estimate and test CU consumption：During the development process, use tools to estimate and test the CU consumption of the contract to ensure it is within limits.
14. Logic errors
Unstaking undestructed tokens (pledge): When unstaking, if the contract does not correctly destroy the corresponding tokens, the total amount of tokens may be inconsistent, thereby affecting the balance of the economic system.
After the pledge pool was reduced, all user funds were not reduced, resulting in the last user being unable to withdraw or transfer funds (pledge): When the pledge pool performs a reduction operation, the failure to adjust the funds of all users accordingly may result in some users being unable to withdraw or transfer funds, resulting in economic losses.
Bypass checks to claim rewards (staking): If there are loopholes in the reward collection logic in the contract, attackers may bypass the check and receive rewards that do not belong to them.
Single order and multiple order types do not match (NFT): In the NFT trading platform, the mismatch between a single order and multiple order types may lead to erroneous trading behaviors and harm the interests of users.
14.1 Bypassing checks to claim rewards (staking)
Vulnerability sample code
In the code below, the user’s staking status is not checked, which may result in ineligible users claiming rewards. Users can claim rewards without any staking.

use std::collections::HashMap;
use solana_program::pubkey::Pubkey;
use solana_program::program_error::ProgramError;

struct StakingContract {
    user_rewards: HashMap<Pubkey, u64>,
    user_stakes: HashMap<Pubkey, u64>,
}

impl StakingContract {
    pub fn claim_reward(&mut self, user: Pubkey) -> Result<(), ProgramError> {
        let reward = self.user_rewards.get(&user).ok_or(ProgramError::InvalidArgument)?;
        // Did not check whether the user is eligible to receive the reward
        self.user_rewards.insert(user, 0);
        Ok(())
    }
}
Security advice
Conduct necessary checks before claiming rewards to ensure that users are eligible to receive rewards.

use std::collections::HashMap;
use solana_program::pubkey::Pubkey;
use solana_program::program_error::ProgramError;

struct StakingContract {
    user_rewards: HashMap<Pubkey, u64>,
    user_stakes: HashMap<Pubkey, u64>,
}

impl StakingContract {
    pub fn claim_reward(&mut self, user: Pubkey) -> Result<(), ProgramError> {
        let reward = self.user_rewards.get(&user).ok_or(ProgramError::InvalidArgument)?;
       
        // Check if the user has pledged
        let stake = self.user_stakes.get(&user).ok_or(ProgramError::InvalidArgument)?;
        if *stake == 0 {
            return Err(ProgramError::InvalidArgument); // Without pledge, you cannot receive rewards
        }

        // Check if the reward is greater than zero
        if *reward == 0 {
            return Err(ProgramError::InvalidArgument); // There are no rewards to receive
        }

        //Execute the collection operation
        self.user_rewards.insert(user, 0);
        Ok(())
    }
}
15. Hard coding
In smart contract development,hardcode(Hardcoding) refers to directly hardcoding certain key parameters or addresses in the code. Hardcoding governance addresses is one of the common problems. For example, in decentralized finance (DeFi) platforms, NFT markets, or staking contracts, the governance address may be hard-coded into the contract. Risks of doing so include:Private key stolen: If the private key corresponding to the hard-coded governance address is stolen, the attacker will be able to control the entire contract, causing serious security issues.Private key lost: If the private key of the governance address is lost and the contract parameters cannot be updated or emergency operations are performed, the contract will be paralyzed.lack of flexibility: The hard-coded governance address cannot be changed dynamically, which limits the contract’s upgradeability and flexibility.
Vulnerability examples
Here is a simple example of a hardcoded governance address:

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
};

const GOVERNANCE_ADDRESS: &str = "HARD_CODED_GOVERNANCE_ADDRESS";

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let signer = next_account_info(account_info_iter)?;

    if signer.key.to_string() != GOVERNANCE_ADDRESS {
        return Err(ProgramError::IllegalOwner);
    }

    //Perform governance operations
    Ok(())
}
In the above example, the governance address is hardcoded into the constant GOVERNANCE_ADDRESS, which means that the governance address cannot be changed dynamically.

Security advice
A mechanism should be designed and implemented so that the governance address can be dynamically updated while ensuring that only the current governance address can perform this update operation.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
    program_error::ProgramError,
    msg,
};

pub struct Governance {
    governance_address: Pubkey,
}

impl Governance {
    pub fn new(governance_address: Pubkey) -> Self {
        Self { governance_address }
    }

    pub fn update_governance(&mut self, new_address: Pubkey, signer: &Pubkey) -> Result<(), ProgramError> {
        if *signer != self.governance_address {
            msg!("Only current governance address can update governance");
            return Err(ProgramError::IllegalOwner);
        }
        self.governance_address = new_address;
        Ok(())
    }
}

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let signer = next_account_info(account_info_iter)?;

    let mut governance = Governance::new(*signer.key);

    // Assuming the instruction data contains the new governance address
    let new_governance_address = Pubkey::new(&instruction_data[0..32]);

    governance.update_governance(new_governance_address, signer.key)?;

    Ok(())
}
In the optimized example, a Governance structure is implemented to manage governance addresses, and an update_governance method is provided to allow the current governance address to be updated to a new address. Only the current governance address can perform this update operation, ensuring security and resiliency.

16. CPI (cross-program call) verification
CPI (Cross-Program Invocation) is a mechanism in Solana that allows one program to call the entry point of another program. Although this mechanism provides flexibility and functional extensibility for development, it also introduces new security risks. Special attention is required:

Vulnerabilities in the way data is passed: In cross-program calls, the correct transfer and verification of data is crucial. Incorrect data transfer or unverified data may lead to program tampering or incorrect data transfer, which may lead to security vulnerabilities.
Holes in the way responses are interpreted: Programs need to properly handle and validate responses returned from other programs to ensure that the returned data is as expected. Improper response handling can lead to incorrect operation or be exploited by attackers.
Vulnerability examples
The following example code demonstrates a vulnerability where data is not properly validated in CPI calls:

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    pubkey::Pubkey,
    sysvar::{net::Rent, Sysvar},
    msg,
    program_error::ProgramError,
};

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let source_account = next_account_info(account_info_iter)?;
    let destination_account = next_account_info(account_info_iter)?;
    let system_program = next_account_info(account_info_iter)?;

    // Build instructions to call other programs
    let ix = solana_program::system_instruction::transfer(
        source_account.key,
        destination_account.key,
        1000,
    );

    // Call other programs without validating data
    invoke(
        &ix,
        &[source_account.clone(), destination_account.clone(), system_program.clone()],
    )?;
   
    Ok(())
}
In the above example, the transfer instruction of the system program is called, but the data is not verified.

Security advice
When making cross-program calls, ensure the correct delivery and validation of data, and properly handle and validate returned responses.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    pubkey::Pubkey,
    sysvar::{net::Rent, Sysvar},
    msg,
    program_error::ProgramError,
};

entrypoint!(process_instruction);

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let source_account = next_account_info(account_info_iter)?;
    let destination_account = next_account_info(account_info_iter)?;
    let system_program = next_account_info(account_info_iter)?;

    // Verify whether the incoming account meets expectations
    if !source_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    //Verify account data
    if source_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Build instructions to call other programs
    let ix = solana_program::system_instruction::transfer(
        source_account.key,
        destination_account.key,
        1000,
    );

    // Call other programs and verify the returned results
    invoke(
        &ix,
        &[source_account.clone(), destination_account.clone(), system_program.clone()],
    )?;

    Ok(())
}
In the optimized example, verification of accounts and data is added to ensure that the called data is correct and the returned results are processed correctly.

17. Syscall security
System calls (Syscalls) are the basis for interaction with the Solana runtime environment. Smart contracts usually require various system calls, such as obtaining account information, reading data, etc. These calls must be used and handled correctly to ensure the security and reliability of the contract.

System call usage: Ensure the correct use of the system calls provided by the Solana runtime to avoid security issues caused by improper use. For example, failure to properly check return values ​​can lead to contract logic errors or security vulnerabilities.
Error handling and validation: Every system call must have appropriate error handling mechanisms to prevent potential security vulnerabilities. Ignoring or improperly handling errors may cause the contract to crash or be exploited by attackers.
Vulnerability examples
The following example code demonstrates a vulnerability where errors are not properly handled when making system calls:

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    program::invoke,
    pubkey::Pubkey,
    sysvar::{net::Rent, Sysvar},
};

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    _instruction_data: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let source_account = next_account_info(account_info_iter)?;
    let destination_account = next_account_info(account_info_iter)?;
    let system_program = next_account_info(account_info_iter)?;

    // Build system call instructions
    let ix = solana_program::system_instruction::transfer(
        source_account.key,
        destination_account.key,
        1000,
    );

    // Call the system program, but the error is not handled
    invoke(
        &ix,
        &[source_account.clone(), destination_account.clone(), system_program.clone()],
    )?;
   
    Ok(())
}
In the above example, the error of the system call is not handled. If the call fails, the contract will not be able to catch and handle the error, which may lead to unexpected behavior.

Security advice
Ensure proper error handling and validation when making system calls.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    pubkey::Pubkey,
    sysvar::{net::Rent, Sysvar},
    msg,
    program_error::ProgramError,
};

entrypoint!(process_instruction);

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let source_account = next_account_info(account_info_iter)?;
    let destination_account = next_account_info(account_info_iter)?;
    let system_program = next_account_info(account_info_iter)?;

    // Build system call instructions
    let ix = solana_program::system_instruction::transfer(
        source_account.key,
        destination_account.key,
        1000,
    );

    // Call system program and handle errors
    match invoke(
        &ix,
        &[source_account.clone(), destination_account.clone(), system_program.clone()],
    ) {
        Ok(_) => msg!("Transfer successful"),
        Err(error) => {
            msg!("Error during transfer: {:?}", error);
            return Err(ProgramError::Custom(0)); // Custom error handling
        }
    }
   
    Ok(())
}
In the optimized example, error handling for system calls is added to ensure that errors can be caught and handled when the call fails, thus improving the reliability and security of the contract.

18. PDA issues
PDA (Program Derived Addresses) is a special address in Solana, which is generated from the program seed and program ID to ensure uniqueness.

Standardization of seeds: Ensure that seeds are properly normalized when generating PDAs to prevent address conflicts or other security issues. If the torrent is not properly normalized, duplicate or unexpected PDAs may be generated, leading to security vulnerabilities.
PDA sharing: PDA sharing involves multiple programs sharing the same PDA, which may pose security risks. Assess the risk of multiple programs sharing the same PDA to ensure the sharing mechanism is safe and reliable. Sharing the same PDA may lead to data leakage or permission abuse.
Vulnerability examples
The following example code demonstrates potential problems with PDA generation without properly normalized seeds and multiple programs sharing the same PDA:

use solana_program::{
    pubkey::Pubkey,
    program_pack::Pack,
    system_instruction,
    sysvar::{net::Rent, Sysvar},
    account_info::{AccountInfo, next_account_info},
    entrypoint::ProgramResult,
    program::invoke_signed,
};

fn create_pda(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    seeds: &[&[u8]],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let payer_account = next_account_info(account_info_iter)?;
    let pda_account = next_account_info(account_info_iter)?;

    let (pda, _bump_seed) = Pubkey::find_program_address(seeds, program_id);

    // Seed not properly normalized
    if *pda_account.key != pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // PDA sharing problem: multiple programs share the same PDA
    // Suppose there is another program using the same seed to generate a PDA

    let rent = Rent::get()?;
    let rent_lamports = rent.minimum_balance(pda_account.data_len());

    let create_pda_instruction = system_instruction::create_account(
        &payer_account.key,
        &pda_account.key,
        clean_lampports,
        pda_account.data_len() as u64,
        program_id,
    );

    invoke_signed(
        &create_pda_instruction,
        &[payer_account.clone(), pda_account.clone()],
        &[&seeds],
    )?;

    Ok(())
}
In the example above, the PDA’s seed is not properly normalized, and there is a potential issue with multiple programs sharing the same PDA.

Security advice
Ensure proper normalization of torrents and assess and avoid risks of PDA sharing.

use solana_program::{
    pubkey::Pubkey,
    program_pack::Pack,
    system_instruction,
    sysvar::{net::Rent, Sysvar},
    account_info::{AccountInfo, next_account_info},
    entrypoint::ProgramResult,
    program::invoke_signed,
    msg,
};

fn create_pda(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    seeds: &[&[u8]],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let payer_account = next_account_info(account_info_iter)?;
    let pda_account = next_account_info(account_info_iter)?;

    let (pda, bump_seed) = Pubkey::find_program_address(seeds, program_id);

    // Correctly normalize seeds
    if *pda_account.key != pda {
        msg!("Invalid PDA seeds");
        return Err(ProgramError::InvalidSeeds);
    }

    // Make sure the PDA is not shared by multiple programs
    // If sharing is required, ensure access control and permission management for each program

    let rent = Rent::get()?;
    let rent_lamports = rent.minimum_balance(pda_account.data_len());

    let create_pda_instruction = system_instruction::create_account(
        &payer_account.key,
        &pda_account.key,
        clean_lampports,
        pda_account.data_len() as u64,
        program_id,
    );

    invoke_signed(
        &create_pda_instruction,
        &[payer_account.clone(), pda_account.clone()],
        &[&seeds],
    )?;

    Ok(())
}
In the optimized example, the correct standardization of seeds and the assessment of PDA sharing risks are added to ensure the safety of PDA generation and use.

Conclusion
Through this article, we take an in-depth look at common security issues when developing smart contracts using the Rust language on the Solana blockchain. We analyzed potential vulnerabilities in many aspects, including integer issues, memory and stack issues, parameter verification issues, initialization issues, DoS attacks, front-running issues, calling unknown code, etc., and put forward corresponding security suggestions.
