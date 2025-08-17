# PDA Privileges Exploit

## Introduction

Program Derived Addresses (PDAs) in Solana can be used to sign transactions on behalf of programs. However, if a PDA is allowed to sign a transaction without proper validation, it can lead to serious privilege escalation vulnerabilities. If a program doesn't verify that a PDA is associated with an authorized creator, an attacker can exploit this to perform unauthorized actions—such as withdrawing funds or manipulating program state.

## Attack Scenario: Unauthorized PDA Signing

The following example demonstrates an insecure implementation where a PDA (`metadata_account`) is allowed to sign a transfer instruction without validating its association with the intended creator:

```rust
pub fn insecure_withdraw(ctx: Context<InsecureWithdraw>) -> Result<()> {
    ...
    let signer_seeds: &[&[&[u8]]] = &[&[b"metadata_account", metadata_account.creator.as_ref(), &[ctx.bumps.metadata_account]]];

    let cpi_context = CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.withdraw_destination.to_account_info(),
            authority: metadata_account.to_account_info(),
        },
        signer_seeds,
    );
    transfer(cpi_context, amount)?;
    ...
}
```

### Vulnerability

In this implementation:

* The `metadata_account.creator` is not validated.
* An attacker can substitute a malicious `metadata_account` and forge a PDA that signs unauthorized transfers.

## Mitigation: Enforcing Ownership Validation on the PDA

To prevent unauthorized PDA usage, the program must enforce ownership constraints:

```rust
#[derive(Accounts)]
pub struct SecureWithdraw<'info> {
    pub creator: Signer<'info>,
    ...
    #[account(
        seeds = [b"metadata_account", metadata_account.creator.key().as_ref()],
        bump,
        has_one = creator,
    )]
    pub metadata_account: Account<'info, MetadataAccount>,
    ...
}
```

### Benefits of This Fix

* Ensures `metadata_account` is explicitly tied to the authorized `creator`.
* Prevents attackers from supplying arbitrary metadata accounts.
* Guarantees that only the legitimate creator can authorize the PDA to sign transactions.

## Conclusion

Allowing a PDA to sign transactions without verifying its association with the correct owner poses significant security risks. Always enforce ownership checks using `has_one` constraints or equivalent logic to ensure only authorized accounts can utilize PDAs for transaction signing.




# 2. 🛡️ Solana Account Data Matching Attack

## 📘 Introduction

Failing to verify that an account contains the expected data before updating it can result in **unauthorized modifications**. If a program does not check that the correct account is being updated, an attacker could manipulate unintended accounts, leading to unauthorized state changes and potential security breaches.

---

## ⚠️ Attack Scenario: Updating an Account Without Validation

The following insecure implementation allows an attacker to update an account’s `data` field **without verifying ownership**:

```rust
pub fn update_vault_data_insecure(ctx: Context<UpdateVaultAuthorityInsecure>, new_data: u8) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    vault.data = new_data;

    Ok(())
}
```

Since there is **no check** to confirm that the `vault_authority` matches the expected owner, **anyone can modify** the vault’s data as long as they provide a valid account reference. This could lead to unauthorized changes that alter protocol behavior or compromise asset integrity.

---

## 🛡️ Mitigation: Ensuring Proper Account Ownership Verification

To prevent this attack, **verify that the `vault_authority` matches the signer** attempting to update the vault:

```rust
pub fn update_vault_data_secure(ctx: Context<UpdateVaultAuthoritySecure>, new_data: u8) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    if vault.vault_authority != ctx.accounts.vault_authority.key() {
        return Err(AccountDataMatchingError::UnauthorizedVaultDataUpdate.into());
    }
    vault.data = new_data;
    Ok(())
}
```

Alternatively, enforce validation using **Anchor constraints**:

```rust
#[account(
    mut,
    constraint = vault.vault_authority == vault_authority.key(),
)]
pub vault: Account<'info, Vault>
```

This ensures that only the **correct vault authority** can modify the account’s data, effectively **preventing unauthorized modifications**.

---

## ✅ Conclusion

Updating account data without verifying ownership introduces serious security risks by allowing **unintended modifications**. Always enforce **explicit ownership checks** using program logic or **Anchor constraints** to ensure only authorized entities can update sensitive account fields.


# 3.  Solana Account Re-Initialization Attack

## Introduction
Solana's `init_if_needed` constraint allows for account initialization if it does not already exist. However, without additional safeguards, this feature can be exploited in a re-initialization attack, where an attacker repeatedly invokes the instruction to overwrite an existing account's data, leading to unintended behavior, state corruption, or unauthorized modifications.

## Attack Scenario: Unprotected Re-Initialization
The following implementation uses `init_if_needed` without validation, allowing an attacker to invoke the instruction multiple times:

```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,
    #[account(
        init_if_needed,
        payer = creator,
        space = 8 + Metadata::LEN,
        seeds = [b"metadata"],
        bump
    )]
    pub metadata: Account<'info, Metadata>,
    pub system_program: Program<'info, System>,
}

pub fn insecure_initializev1(
    ctx: Context<Initialize>,
    parameters: InitializeParameters,
) -> Result<()> {
    let metadata = &mut ctx.accounts.metadata;
    metadata.creator = ctx.accounts.creator.key();
    metadata.name = parameters.name;
    metadata.symbol = parameters.symbol;
    metadata.uri = parameters.uri;
    metadata.year_of_creation = parameters.year_of_creation;
    Ok(())
}
```

Since there is no mechanism to prevent multiple initializations, an attacker can invoke this instruction again with different parameters, overwriting critical account data and altering protocol behavior.

## Mitigation: Implementing an Initialization Flag
Avoid using `init_if_needed` whenever possible. If it must be used, implement an explicit flag to track whether the account has already been initialized:

```rust
pub fn secure_initialize(
    ctx: Context<Initialize>,
    parameters: InitializeParameters,
) -> Result<()> {
    let metadata = &mut ctx.accounts.metadata;

    if !metadata.is_initialized {
        metadata.creator = ctx.accounts.creator.key();
        metadata.name = parameters.name;
        metadata.symbol = parameters.symbol;
        metadata.uri = parameters.uri;
        metadata.year_of_creation = parameters.year_of_creation;
        metadata.is_initialized = true;
    } else {
        panic!("Account already initialized");
    }
    Ok(())
}
```

This ensures that once an account has been initialized, subsequent attempts to reinitialize it will fail, preventing data overwrites and unauthorized modifications.

## Conclusion
Unrestricted use of `init_if_needed` leaves programs vulnerable to state corruption and unauthorized modifications through repeated invocations. Implement an explicit `is_initialized` flag to prevent re-initialization and ensure account integrity throughout the program's lifecycle.


# 4. Introduction
Solana programs interact with external accounts rather than maintaining internal storage, which can lead to synchronization issues when those accounts are modified during a Cross-Program Invocation (CPI). Specifically, Solana does not automatically reload an account after it has been modified by a CPI, meaning subsequent instructions in the same transaction may work with outdated data.

This vulnerability, known as an **account reloading attack**, occurs when a program fails to manually reload an account after a CPI modification. Attackers can exploit this to execute unintended transactions, manipulate protocol states, or bypass security checks based on stale account data.

# Understanding Solana Account Reloading
When an account is modified by a CPI, its updated state is not immediately reflected in the original transaction context. Developers must manually reload the account to ensure they are working with the latest data.

In Solana’s **Anchor framework**, accounts can be reloaded using the `.reload()` function. If this step is omitted, the program may proceed with outdated information, potentially leading to serious security flaws.

# Attack Scenario: Failure to Reload Accounts
Consider a scenario where a program updates an account through a CPI but does not reload the account afterwards. The following example illustrates this insecure behaviour:

```rust
pub fn update_cpi_noreload(ctx: Context<UpdateCPI>, new_input: u8) -> Result<()> {
    ...
    let cpi_context = CpiContext::new(
        ctx.accounts.update_account.to_account_info(),
        update_account::cpi::accounts::Update {
            authority: ctx.accounts.authority.to_account_info(),
            metadata: ctx.accounts.metadata.to_account_info(),
        },
    );

    update_account::cpi::update(cpi_context, new_input)?;
    ...
}
```

## Breakdown of the vulnerability:
- The function calls a CPI (`update_account::cpi::update`) that modifies `metadata`.
- However, the `metadata` account is **not reloaded** after the CPI modification.
- Any subsequent operations in the same transaction that depend on `metadata` may use stale data, leading to incorrect logic execution.
- Attackers can exploit this to manipulate calculations, bypass authentication checks, or even execute transactions with outdated account states.

# Mitigation Strategies: Ensuring Account Reloading
To prevent account reloading attacks, always call `.reload()` on any account that has been modified by a CPI before using it again in the same transaction.

## Secure implementation:
```rust
pub fn update_cpi_reload(ctx: Context<UpdateCPI>, new_input: u8) -> Result<()> {
    ...
    let cpi_context = CpiContext::new(
        ctx.accounts.update_account.to_account_info(),
        update_account::cpi::accounts::Update {
            authority: ctx.accounts.authority.to_account_info(),
            metadata: ctx.accounts.metadata.to_account_info(),
        },
    );

    update_account::cpi::update(cpi_context, new_input)?;

    // Ensuring the updated account state is reloaded
    ctx.accounts.metadata.reload()?;
    ...
}
```

## Key improvements:
- After modifying `metadata` in the CPI, we call `ctx.accounts.metadata.reload()?` to ensure that the account’s latest state is used in subsequent operations.
- This prevents stale data issues and ensures correct logic execution.

# Conclusion
Failure to reload accounts after a Cross-Program Invocation can lead to security vulnerabilities, allowing attackers to exploit outdated data for unintended transactions, bypass security checks, or manipulate protocol states. Developers should always call `.reload()` on accounts modified during CPIs to ensure they are working with the most up-to-date data.



#5    Solana Account Revival Attacks

## Introduction
Solana programs rely on external accounts to store state, unlike Ethereum’s internal contract storage. When closing an account, the Solana runtime garbage collects it only if the account’s balance is reduced to zero and it is no longer rent-exempt. However, if an attacker can prevent an account from being garbage collected after a program marks it as closed, they can revive it and use it in unintended ways.

This vulnerability, known as a **revival attack**, occurs when an account is improperly closed, allowing an attacker to keep using it for unauthorized transactions, drain protocol funds, or exploit re-initialization bugs.

---

## Understanding Solana Accounts
### Closing an Account Improperly Opens an Opportunity for Revival Attacks
The Solana runtime garbage collects accounts when they are no longer rent-exempt. Closing accounts involves transferring the lamports stored in the account for rent exemption to another account of your choosing.

You can use the Anchor `#[account(close = <address_to_send_lamports>)]` constraint to securely close accounts and set the account discriminator to the `CLOSED_ACCOUNT_DISCRIMINATOR`:

```rust
#[account(mut, close = receiver)]
pub data_account: Account<'info, MyData>,
#[account(mut)]
pub receiver: SystemAccount<'info>
```

While it sounds simple, closing accounts properly can be tricky. There are a number of ways an attacker could circumvent having the account closed if you don't follow specific steps.

---

## Attack Scenario: Insecure Account Closing
In Solana, closing an account involves transferring its lamports to another account, which triggers the runtime garbage collection process. Once this happens, the ownership of the closed account is reset from the owning program back to the system program.

### Example of an Insecure Closure Process
The following example demonstrates an insecure account closure process. The instruction requires two accounts:
- `account_to_close` – The account intended for closure.
- `destination` – The recipient of the lamports from the closed account.

The program logic is designed to close an account by simply increasing the destination account's lamports by the amount stored in `account_to_close` and setting `account_to_close` lamports to `0`. With this program, after a full transaction is processed, `account_to_close` will be garbage collected by the runtime.

```rust
pub fn close(ctx: Context<Close>) -> ProgramResult {
    let dest_starting_lamports = ctx.accounts.destination.lamports();

    **ctx.accounts.destination.lamports.borrow_mut() = dest_starting_lamports
       .checked_add(ctx.accounts.account_to_close.to_account_info().lamports())
       .unwrap();
    **ctx.accounts.account_to_close.to_account_info().lamports.borrow_mut() = 0;
    Ok(())
}
```

### How Attackers Exploit This
Garbage collection does not take place until the transaction is fully executed. Since a transaction can contain multiple instructions, an attacker can exploit this delay by including an instruction to close the account while simultaneously adding another instruction to refund its rent-exemption lamports before the transaction completes. 

This prevents the account from being garbage collected, allowing the attacker to reuse the account for unintended actions, potentially leading to exploits such as reward manipulation or protocol fund drainage.

---

## Mitigation Strategies: Secure Account Closing
### Use the Anchor `close` Constraint
Fortunately, Anchor makes secure account closure simpler with the `#[account(close = <target_account>)]` constraint. This constraint handles everything required to securely close an account:

- Transfers the account's lamports to the given `<target_account>`
- Zeroes out the account data
- Sets the account discriminator to the `CLOSED_ACCOUNT_DISCRIMINATOR` variant

All you have to do is add it in the account validation struct to the account you want closed:

```rust
#[derive(Accounts)]
pub struct CloseAccount {
    #[account(
        mut,
        close = receiver
    )]
    pub data_account: Account<'info, MyData>,
    #[account(mut)]
    pub receiver: SystemAccount<'info>
}
```

---

## Conclusion
Improperly closing Solana accounts creates serious **revival attack** risks, allowing attackers to reuse accounts for unauthorized actions, such as draining rewards, manipulating state, or even causing denial-of-service attacks. 

By implementing secure account closure techniques—such as using Anchor’s close constraint (preferable), zeroing out account data, enforcing closed account discriminators, or implementing a force defund function—developers can ensure that accounts are truly closed and cannot be revived for malicious purposes.


#6  # Arbitrary CPI Attacks in Solana

## Introduction
Solana programs frequently rely on **Cross-Program Invocations (CPIs)** to execute logic from other on-chain programs. If a program does not verify that it is calling the correct target program, attackers can pass a malicious program ID instead, hijacking execution and performing unintended operations. This oversight gives an attacker full control over the CPI’s behavior, allowing them to manipulate accounts, bypass security checks, or execute unauthorized transactions.

This attack occurs when a program **accepts an externally supplied program ID without validation** and invokes it blindly. The attacker can inject a custom program that behaves maliciously while appearing to follow expected logic.

## Understanding Arbitrary CPI Attacks
Solana CPIs allow a program to interact with another program by specifying a **target program ID** and required accounts. The problem arises when a program blindly trusts an external program ID and invokes it without confirming its authenticity. If an attacker supplies their own program instead of the expected one, they can redirect execution and implement custom logic that compromises the system.

Verifying the program ID before performing a CPI ensures that only the intended logic executes. If this check is missing, the attacker gains complete control over how the CPI behaves, allowing them to introduce security risks.

## Attack Scenario: Calling an Arbitrary Program Without Validation

```rust
pub fn insecure_verify_pin(
    ctx: Context<InsecureVerifyPinCPI>,
    ...
) -> Result<()> {
    let cpi_program = ctx.accounts.secret_program.to_account_info();

    let cpi_accounts = VerifyPin {
        author: ctx.accounts.author.to_account_info(),
        secret_information: ctx.accounts.secret_information.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

    arbitrary_cpi_expected::cpi::verify_pin(cpi_ctx, pin1, pin2, pin3, pin4)?;
    ...
}
```

### Breakdown of the vulnerability:
- `ctx.accounts.secret_program` is **taken as input without verification**.
- Since the **program ID is not checked**, an attacker can substitute their own malicious program.
- The CPI call will execute logic from the attacker’s program, potentially manipulating data or bypassing security checks.
- The **Solana runtime does not enforce which program gets called in a CPI**, so explicit verification is required to prevent unauthorized execution.

## Mitigation Strategies: Ensuring Program ID Validation
To prevent arbitrary CPI attacks, **always verify that the program being called is the expected program before making the CPI**. The correct approach is to explicitly check the program ID before execution.

### Secure Implementation:

```rust
pub fn secure_verify_pin(
    ctx: Context<SecureVerifyPinCPI>,
    ...
) -> Result<()> {
    let cpi_program = ctx.accounts.secret_program.to_account_info();

    if cpi_program.key() != arbitrary_cpi_expected::ID {
        return err!(ArbitraryCPIError::CPIProgramIDMismatch);
    }

    let cpi_accounts = VerifyPin {
        author: ctx.accounts.author.to_account_info(),
        secret_information: ctx.accounts.secret_information.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

    arbitrary_cpi_expected::cpi::verify_pin(cpi_ctx, pin1, pin2, pin3, pin4)?;
    ...
}
```

### Key Improvements:
- Before making the CPI, the program **checks if `ctx.accounts.secret_program` matches the expected `arbitrary_cpi_expected::ID`**.
- If the check fails, the **transaction is aborted**, preventing any unintended execution.
- This approach eliminates the risk of an attacker injecting a **malicious program** into the CPI call.

## Conclusion
Blindly accepting an externally supplied program ID in a Solana CPI is a **serious security risk**. If an attacker substitutes a malicious program, they can manipulate execution flow, override expected logic, and gain unauthorized control over protocol operations.

By **verifying the program ID before executing a CPI**, developers can ensure that only the correct logic runs, effectively mitigating this class of attack.

# Bump Seed Canonicalization Attack

## Introduction

Solana PDAs are derived using a set of seeds and a bump seed. If a program uses `create_program_address` with a user-supplied bump **without enforcing canonicality**, it can result in **multiple valid PDAs for the same seed inputs**. This undermines the uniqueness of PDAs and opens up potential attack surfaces where a user can create multiple valid accounts for the same logical identity, leading to inconsistent state and unauthorized actions.

---

## Attack Scenario: Arbitrary Bump with Non-Canonical Derivation

```rust
pub fn set_value(ctx: Context<BumpSeed>, key: u64, new_value: u64, bump: u8) -> Result<()> {
    let address = Pubkey::create_program_address(
        &[key.to_le_bytes().as_ref(), &[bump]],
        ctx.program_id
    )?;

    if address != ctx.accounts.data.key() {
        return Err(ProgramError::InvalidArgument.into());
    }

    ctx.accounts.data.value = new_value;
    Ok(())
}

#[derive(Accounts)]
pub struct BumpSeed<'info> {
    #[account(mut)]
    pub data: Account<'info, Data>,
}

#[account]
pub struct Data {
    pub value: u64,
}
```

In this implementation, the bump is passed from the user. While the PDA is validated, there is **no enforcement of the canonical bump**. A malicious user can generate and initialize multiple accounts with different valid bumps, breaking the intended one-to-one mapping of seeds to accounts.

---

## Mitigation: Enforce Canonical Bump via `find_program_address`

```rust
pub fn set_value_secure(ctx: Context<BumpSeed>, key: u64, new_value: u64, bump: u8) -> Result<()> {
    let (expected_address, expected_bump) = Pubkey::find_program_address(
        &[key.to_le_bytes().as_ref()],
        ctx.program_id
    );

    if ctx.accounts.data.key() != expected_address || bump != expected_bump {
        return Err(ProgramError::InvalidArgument.into());
    }

    ctx.accounts.data.value = new_value;
    Ok(())
}
```

This ensures that only the PDA using the **canonical bump** is valid. To optimize for future calls, the bump should be stored inside the PDA’s account data during initialization and reused in subsequent validations.

---

## Conclusion

Allowing arbitrary bumps in PDA derivations **weakens the assumption of uniqueness** in seed-based addressing. Always derive PDAs using `find_program_address` to enforce canonicality, and validate bump correctness explicitly or via Anchor constraints to avoid unauthorized account creation.


# Duplicate Mutable Accounts in Solana Programs

## Introduction
When a Solana instruction processes multiple mutable accounts of the same type, an attacker can pass the same account multiple times, leading to unintended state modifications. This vulnerability allows bypassing expected logic, manipulating balances, or causing incorrect state updates.

## Attack Scenario: Using the Same Account Twice
The following implementation does not prevent duplicate accounts from being passed:

```rust
pub fn insecure_atomic_trade(ctx: Context<AtomicTrade>, transfer_amount: u64) -> Result<()> {
    ...
    let fee = transfer_amount
        .checked_mul(FEE_BPS)
        .unwrap()
        .checked_div(BPS)
        .unwrap();

    let fee_deducted = transfer_amount.checked_sub(fee).unwrap();

    fee_vault.amount = fee_vault.amount.checked_add(fee).unwrap();
    vault_a.amount = vault_a.amount.checked_add(fee_deducted).unwrap();
    vault_b.amount = vault_b.amount.checked_sub(fee_deducted).unwrap();
    ...
}
```

If the attacker sets `vault_a` and `vault_b` to the same account, the program will add and subtract from the same balance, potentially leading to incorrect deductions, infinite balance increases, or logic inconsistencies.

## Mitigation: Ensuring Unique Account Inputs
To prevent this attack, enforce a check ensuring distinct accounts:

```rust
pub fn secure_atomic_trade(ctx: Context<AtomicTrade>, transfer_amount: u64) -> Result<()> {
    ...
    if vault_a.key() == vault_b.key() {
        return err!(AtomicTradeError::DuplicateVaults);
    }

    let fee = transfer_amount
        .checked_mul(FEE_BPS)
        .unwrap()
        .checked_div(BPS)
        .unwrap();
    ...
}
```

Alternatively, you can use Anchor constraints:

```rust
#[account(
    ...
    constraint = vault_a.key() != vault_b.key() @ AtomicTradeError::DuplicateVaults,
    ...
)]
pub vault_a: Account<'info, Vault>
```

This ensures that an instruction cannot be executed with the same account passed twice.

## Conclusion
Allowing duplicate mutable accounts without validation can lead to balance manipulation, unintended logic execution, and potential exploits. Always enforce uniqueness checks using explicit conditions or Anchor constraints to maintain transaction integrity.



# Solana Program Front-run Initialization

## Introduction
Frontrunning in Solana occurs when an attacker preempts a transaction by submitting a conflicting one with a higher priority. If an initialization instruction does not verify the initializer’s identity, an attacker can front-run the transaction and take control of a critical account, leading to a denial of service or unauthorized protocol configuration.

## Attack Scenario: Unrestricted Global Configuration Initialization
The following implementation allows any signer to initialize the `global_config` account:

```rust
#[derive(Accounts)]
pub struct InitializeInsecure<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(
        init,
        payer = signer,
        space = 8 + GlobalConfig::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub global_config: Account<'info, GlobalConfig>,
    pub system_program: Program<'info, System>,
}
```

Since there is no identity verification, an attacker can monitor transactions and front-run the legitimate initializer. By submitting their own transaction first, they gain control of `global_config`, preventing the intended initializer from setting up the account and potentially locking the protocol into an unusable state.

## Mitigation: Restrict Initialization to the Upgrade Authority
To prevent this, enforce a strict identity check ensuring only the upgrade authority can initialize the config:

```rust
#[derive(Accounts)]
pub struct InitializeSecure<'info> {
    #[account(
        mut,
        constraint = signer.key() == program_data.upgrade_authority_address.unwrap_or_default()
    )]
    pub signer: Signer<'info>,
    #[account(
        init,
        payer = signer,
        space = 8 + GlobalConfig::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub global_config: Account<'info, GlobalConfig>,
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = bpf_loader_upgradeable::id(),
    )]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}
```

This ensures that only the upgrade authority, the entity responsible for managing the program, can initialize `global_config`, eliminating the risk of frontrunning by unauthorized users.

## Conclusion
Failing to verify the initializer’s identity allows attackers to preempt account initialization, leading to unauthorized control or a denial of service. Always restrict initialization to the upgrade authority or an explicitly defined trusted entity to ensure secure setup of critical accounts.


# Solana Program Front-run Initialization

## Introduction
Frontrunning in Solana occurs when an attacker preempts a transaction by submitting a conflicting one with a higher priority. If an initialization instruction does not verify the initializer’s identity, an attacker can front-run the transaction and take control of a critical account, leading to a denial of service or unauthorized protocol configuration.

## Attack Scenario: Unrestricted Global Configuration Initialization
The following implementation allows any signer to initialize the `global_config` account:

```rust
#[derive(Accounts)]
pub struct InitializeInsecure<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(
        init,
        payer = signer,
        space = 8 + GlobalConfig::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub global_config: Account<'info, GlobalConfig>,
    pub system_program: Program<'info, System>,
}
```

Since there is no identity verification, an attacker can monitor transactions and front-run the legitimate initializer. By submitting their own transaction first, they gain control of `global_config`, preventing the intended initializer from setting up the account and potentially locking the protocol into an unusable state.

## Mitigation: Restrict Initialization to the Upgrade Authority
To prevent this, enforce a strict identity check ensuring only the upgrade authority can initialize the config:

```rust
#[derive(Accounts)]
pub struct InitializeSecure<'info> {
    #[account(
        mut,
        constraint = signer.key() == program_data.upgrade_authority_address.unwrap_or_default()
    )]
    pub signer: Signer<'info>,
    #[account(
        init,
        payer = signer,
        space = 8 + GlobalConfig::INIT_SPACE,
        seeds = [b"config"],
        bump
    )]
    pub global_config: Account<'info, GlobalConfig>,
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = bpf_loader_upgradeable::id(),
    )]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}
```

This ensures that only the upgrade authority, the entity responsible for managing the program, can initialize `global_config`, eliminating the risk of frontrunning by unauthorized users.

## Conclusion
Failing to verify the initializer’s identity allows attackers to preempt account initialization, leading to unauthorized control or a denial of service. Always restrict initialization to the upgrade authority or an explicitly defined trusted entity to ensure secure setup of critical accounts.


# Ownership Check: Securing Token Accounts in Solana

## Introduction

Failing to verify account ownership allows an attacker to substitute arbitrary accounts, leading to unauthorized actions.  
If a program does not confirm that a token account belongs to the expected owner and is associated with the correct mint, an attacker can inject a malicious token account to manipulate balances or gain access to funds they do not own.

---

## Attack Scenario: Missing Ownership and Mint Verification

The following insecure implementation does **not** enforce ownership validation, allowing an attacker to pass in arbitrary token accounts:

```rust
pub fn insecure_log_balance_v1(ctx: Context<InsecureOwnershipv1>) -> Result<()> {
    msg!(
        "The balance: {} of Token Account: {} corresponds to owner: {} and Mint: {}",
        ctx.accounts.token_account.amount,
        ctx.accounts.token_account.key(),
        ctx.accounts.token_account_owner.key(),
        ctx.accounts.mint.key(),
    );
    Ok(())
}

#[derive(Accounts)]
pub struct InsecureOwnershipv1<'info> {
    pub mint: Account<'info, Mint>,
    pub token_account: Account<'info, TokenAccount>,
    pub token_account_owner: Signer<'info>,
}
```

**Problem:**  
Since `token_account` ownership and mint association are not validated, an attacker can supply any token account — potentially gaining access to funds or manipulating balances.

---

## Mitigation: Enforcing Ownership and Mint Verification

To prevent unauthorized token account usage, enforce strict ownership and mint constraints:

```rust
#[derive(Accounts)]
pub struct SecureOwnershipv1<'info> {
    pub mint: Account<'info, Mint>,
    #[account(
        token::authority = token_account_owner,
        token::mint = mint
    )]
    pub token_account: Account<'info, TokenAccount>,
    pub token_account_owner: Signer<'info>,
}
```

This ensures that:
- `token_account` is **owned** by `token_account_owner`, preventing unauthorized access.
- `token_account` is **associated** with the provided `mint`, blocking injection of arbitrary accounts.

---

## Conclusion

Without verifying token ownership and mint association, attackers can pass in malicious token accounts, enabling unauthorized transactions and fund access.

**Always enforce explicit constraints on token accounts** to ensure only legitimate owners and mint associations are allowed. This simple check could save your protocol from catastrophic vulnerabilities.


# Signer Authorization Attack

## Introduction

In Solana, marking an account as a `Signer` ensures that the private key signed the transaction, but it does **not** automatically validate whether the signer is **authorized** to act on a specific account. If a program relies solely on the `Signer` constraint without verifying that the signer matches a stored authority, an attacker can exploit this to perform unauthorized actions, such as modifying sensitive state.

---

## Attack Scenario: Missing Authority Validation

The following implementation allows **any signer** to modify the escrow data without validating their authority:

```rust
pub fn insecure_authorization(ctx: Context<InsecureAuthorization>, data: u8) -> Result<()> {
    let escrow = &mut ctx.accounts.escrow;
    escrow.data = data;
    ...
}

#[derive(Accounts)]
pub struct InsecureAuthorization<'info> {
    pub authority: Signer<'info>,
    /// CHECK: This is not correct
    #[account(
        mut,
        seeds = [b"escrow".as_ref()],
        bump
    )]
    pub escrow: Account<'info, Escrow>,
}

#[account]
pub struct Escrow {
    pub authority: Pubkey,
    pub data: u8,
}
```

In this case, although `authority` is a signer, the program does not check if it matches `escrow.authority`. This allows **any wallet** to sign and update `escrow.data` as long as they pass in a valid signer and the correct PDA.

---

## Mitigation: Enforce Explicit Authority Checks

To prevent this, ensure the signer’s address matches the authority stored in the account by using either program logic or Anchor constraints.

### Manual Check

```rust
pub fn secure_authorization(ctx: Context<SecureAuthorization>, data: u8) -> Result<()> {
    let escrow = &mut ctx.accounts.escrow;

    if escrow.authority != ctx.accounts.authority.key() {
        return Err(ErrorCode::Unauthorized.into());
    }

    escrow.data = data;
    ...
}
```

### Anchor Constraint

```rust
#[derive(Accounts)]
pub struct SecureAuthorization<'info> {
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"escrow".as_ref()],
        bump,
        has_one = authority
    )]
    pub escrow: Account<'info, Escrow>,
}
```

This ensures that **only the correct authority** associated with the `Escrow` account can execute the instruction, even if multiple signers are involved in the transaction.

---

## Conclusion

Assuming a signer is authorized without validating their link to the on-chain state introduces critical authorization flaws. **Always** verify signer identity against stored authority fields, either through explicit checks or `has_one` constraints, to ensure only trusted parties can modify protected data.


# Type Cosplay Attack

## Introduction

In Solana, accounts are deserialized based on their byte size rather than an enforced type system. If two account structures have the same size but different intended uses, an attacker can pass one in place of another. Without explicit type validation, the program may deserialize an unintended account, leading to logic inconsistencies, unauthorized access, or data corruption.

## Attack Scenario: Deserializing an Incorrect Account Type

In this example, User and UserMetadata both occupy 68 bytes, allowing one to be deserialized as the other:

```rust
#[account]
pub struct User {
    pub authority: Pubkey,
    pub metadata_account: Pubkey,
    pub age: u32,
}

#[account]
pub struct UserMetadata {
    pub authority: Pubkey,
    pub user_account: Pubkey,
    pub pin1: u8,
    pub pin2: u8,
    pub pin3: u8,
    pub pin4: u8,
}
```

Since there is no type discriminator, the following function incorrectly deserializes UserMetadata as a User account without validation:

```rust
pub fn insecure_user_read(ctx: Context<InsecureTypeCosplay>) -> Result<()> {
    let user = User::try_from_slice(&ctx.accounts.user.data.borrow())?;
    ...
}

#[derive(Accounts)]
pub struct InsecureTypeCosplay<'info> {
    /// CHECK: unsafe, does not check the Account type
    pub user: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
```

If an attacker passes a UserMetadata account instead of User, the program will incorrectly interpret its fields, leading to unintended logic execution.

## Mitigation: Enforcing Type Validation with Discriminators

To prevent type cosplay, enforce strict type validation using account discriminators and explicit type enforcement:

```rust
pub fn secure_user_read(ctx: Context<SecureTypeCosplay>) -> Result<()> {
    let user = &ctx.accounts.user;
    ...
}

#[derive(Accounts)]
pub struct SecureTypeCosplay<'info> {
    #[account(
        has_one = authority,
    )]
    pub user: Account<'info, User>,
    pub authority: Signer<'info>,
}
```

Anchor automatically prepends a discriminator (an 8-byte identifier) to each account and verifies its type before deserialization, preventing unintended type casting.

## Conclusion

Deserializing accounts without enforcing type validation introduces type confusion vulnerabilities, allowing attackers to bypass logic checks by passing structurally similar accounts. Always use account discriminators and Anchor’s type validation to ensure only the correct account type is processed.


