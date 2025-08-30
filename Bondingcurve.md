Bonding curve  deepdive
https://substack.com/inbox/post/161302339


# Audit 1

1. High Findings
2. 
1.1 Incorrect Comparison in buy_token Leading to Graduation
   
Threshold Violation

Description
In the buy_token function, the comparison between net_buy_amount and
max_buy_amount_with_fees is incorrect. The issue arises because max_buy_amount_with_fees
represents the remaining tokens in the bonding curve after adding fees, while net_buy_amount is the
user's token amount after subtracting fees.
This mismatch can cause the function to allow purchases beyond the graduation threshold, leading to
users paying more for fewer tokens at an inflated price.
Impact
This issue Leads to Graduation Threshold Violation which is core variant in the system , and results in
users buying more tokens at a much higher price than expected due to exceeding the bonding curve’s
graduation threshold. Specifically, the bonding curve’s SOL reserves ( sol_reserves ) can exceed the
intended graduation reserve, leading to unfair pricing and potential loss of funds for the user.

Scenario:

Amount in: 55 SOL

Fee: 10% (0.1)
Max amount without fees: 45 SOL
Max amount with fees: 50 SOL
Net buy amount: 49.5 SOL
Current Condition:

```rust
if net_buy_amount <= max_buy_amount_with_fees {
 actual_buy_amount = net_buy_amount; // amount after taking fees
 actual_swap_fee = swap_fee;
} else {
 actual_buy_amount = max_buy_amount_without_fees; // amount without
taking fees
 actual_swap_fee = max_buy_amount_with_fees
 .checked_sub(max_buy_amount_without_fees)
 .unwrap();
};
Actual Values in This Scenario:
actual_buy_amount: 49.5 SOL
actual_swap_fee: 5.5 SOL
Since actual_buy_amount is incorrectly calculated since it is greater than Max amount without
fees which is the actual amount of sol need in the curve , the bonding curve’s reserves are updated
incorrectly:
ctx.accounts.bonding_curve.sol_reserves = ctx
 .accounts
 .bonding_curve
 .sol_reserves
 .checked_add(actual_buy_amount)
 .unwrap();
```

This results in the bonding curve surpassing the graduation threshold, causing users to receive fewer
tokens than expected while paying an inflated price.

Recommendation

The net_buy_amount should be compared with max_buy_amount_without_fees , and the equal sign
should be removed from the condition:
```rust

- if net_buy_amount <= max_buy_amount_with_fees {
+ if net_buy_amount < max_buy_amount_without_fees {
 actual_buy_amount = net_buy_amount; // amount after taking fees
 actual_swap_fee = swap_fee;
} else {
 actual_buy_amount = max_buy_amount_without_fees; // amount without
taking fees
 actual_swap_fee = max_buy_amount_with_fees
 .checked_sub(max_buy_amount_without_fees)
 .unwrap();
 //@audit-issue The curve should be marked as graduated here.
};
```

This correction ensures that the bonding curve does not exceed the graduation threshold, preventing
unfair pricing and loss of funds.


# 2. Medium Findings
2.1 Slippage Protection Bypass in buy_token

Description

In the buy_token and sell_token functions, users can specify a slippage parameter to protect their
trades from executing at unfavorable prices. This is enforced by checking the trade’s resulting amount
against the user's slippage constraints.
However, in the buy_token function, the input amounts are adjusted based on the remaining amount
before reaching the graduation threshold. This adjustment overrides the user's originally intended trade
amount, making the amount_out_min parameter ineffective.

Issue in Code:
```rust
actual_buy_amount = max_buy_amount_without_fees; // amount without taking
fees
actual_swap_fee = max_buy_amount_with_fees
 .checked_sub(max_buy_amount_without_fees)
 .unwrap();
```
Since actual_buy_amount is set to max_buy_amount_without_fees , the final trade execution does
not respect the user’s original slippage constraints, as amount_out_min was set based on the user's
initial amount_in .
Impact
The trade can execute at a price worse than what the user intended.
Users are exposed to price slippage beyond their specified tolerance.
This results in a loss of funds, as trades may complete at unpreferred or unfair prices.
Recommendation
To maintain slippage protection, a slippage factor should be calculated based on the original input
amounts. This factor should then be applied to the adjusted amounts to ensure the final trade respects
the user's slippage constraints.

# 3. Low Findings

3.1 Incorrect Macro Usage for Pubkey Comparison

Description

The require_neq! macro is used to ensure two non-Pubkey values are not equal. However, in the
given code snippet, it is incorrectly used to compare two public keys:
require_neq!(creator, Pubkey::default(), ErrorCode::CreatorIsNotProvided);
According to the documentation, require_neq! should not be used for Pubkey comparisons. Instead,
require_keys_neq! is the appropriate macro for comparing two public keys.
/// Ensures two NON-PUBKEY values are not equal.
///
/// Use [require_keys_neq](crate::prelude::require_keys_neq)
/// to compare two pubkeys.
///
/// Can be used with or without a custom error code.
///
/// # Example
/// ```rust,ignore
/// pub fn set_data(ctx: Context<SetData>, data: u64) -> Result<()> {
/// require_neq!(ctx.accounts.data.data, 0);
/// ctx.accounts.data.data = data;
/// Ok(());
/// }
/// ```

Recommendation

Replace require_neq! with require_keys_neq! when comparing public keys to ensure proper
validation:
require_keys_neq!(creator, Pubkey::default(),
ErrorCode::CreatorIsNotProvided);

3.2 Insecure Authority Transfer Leading to Potential DoS
Description
In the transfer_authority function, if the authority is transferred to an invalid or inaccessible
address, it could result in a complete denial of service (DoS) for protocol configurations and core
functionalities. Since there is no verification mechanism ensuring that the new_authority is a valid
and active entity, the protocol may become permanently locked if an incorrect address is set.

Recommendation

To prevent this issue, it is recommended to:

1. Require the new authority to be a signer for the transaction, ensuring that they acknowledge and
accept the role.
2. Implement a two-step authority transfer process by introducing a claim_authority function.
This approach ensures that the new authority explicitly claims their role before the transfer is
finalized.

Suggested Fix: Require the New Authority as a Signer

Modify the TransferAuthority struct to enforce that the new_authority signs the transaction:
#[derive(Accounts)]
pub struct TransferAuthority<'info> {
 pub authority: Signer<'info>, // Current authority
 #[account(mut, has_one = authority @ ErrorCode::Unauthorized)]
 pub config: Account<'info, Config>, // The config account whose
authority is being transferred
 pub new_authority: Signer<'info>, // Ensure the new authority is a valid
signer
 pub system_program: Program<'info, System>,
}
This ensures that the new_authority is actively participating in the transfer, preventing accidental or
malicious misconfiguration.
3.3 Setting the destination address to a PDA of a Token Account
Closure Leading to SOL Lock
Description
Closing a token account transfers its SOL balance to the specified destination account. However, the
destination account must be able to move SOL. Setting the destination to a PDA can result in locked
SOL since a PDA cannot directly move SOL.
In the following function call, the destination is set to a PDA:
close_vault(
 &ctx.accounts.token_program,
 &ctx.accounts.bonding_curve_vault.to_account_info(),
 &ctx.accounts.vault_authority.to_account_info(),
@> &ctx.accounts.recipient_token_account.to_account_info(),
 vault_authority_signer,
)?;
This setup causes SOL to be locked until recipient_token_account is closed.
Recommendation
Set the destination address to the recipient directly instead of a PDA. This ensures that the recipient
can receive and move the SOL immediately after closure.
3.4 Missing Validation for Raydium Program Address
Description
In the swap_tokens_for_sol_on_raydium function, the Raydium program address
( cp_swap_program ) is not explicitly validated.
The current implementation:
/// input_token_mint and output_token_mint have the same token program
pub token_program: Interface<'info, TokenInterface>,
pub cp_swap_program: Program<'info, RaydiumCpmm>,
Recommendation
To enforce security and ensure the correct Raydium program is used, add explicit validation by
specifying the expected address:
#[account(address = raydium_cpmm_cpi::ID)]
pub cp_swap_program: Program<'info, RaydiumCpmm>,
3.5 Missing Validation for amount > 0 in wrap Function
Description
The wrap function is expected to validate that the amount parameter is greater than zero before
proceeding. However, no such validation is currently implemented. This contradicts the function's
documentation, which states that an error should be thrown if amount is zero.
Current implementation:
pub fn wrap(ctx: Context<Wrap>, amount: u64) -> Result<()> {
 let transfer_accounts = TransferChecked {
 from: ctx.accounts.depositor_boop_token_account.to_account_info(),
 mint: ctx.accounts.boop.to_account_info(),
 to: ctx.accounts.boop_vault.to_account_info(),
 authority: ctx.accounts.depositor.to_account_info(),
 };
 let cpi_ctx = CpiContext::new(
 ctx.accounts.token_program.to_account_info(),
 transfer_accounts,
 );
 transfer_checked(cpi_ctx, amount, ctx.accounts.boop.decimals)?;
Without this check, the function may proceed with an invalid zero-amount transfer.

Recommendation

Add a validation check to ensure that amount is greater than zero:
require!(amount > 0, ErrorCode::ZeroAmount);
This ensures that the function behaves as documented and prevents unintended zero-value transfers.
3.6 Missing Validation for protocol_fee_recipient in
update_config

Description

In the update_config function, the protocol_fee_recipient address is updated without validation.
If the recipient address is set to the default Pubkey::default() , it can lead to a denial-of-service
(DoS) issue, preventing core protocol functionalities from operating correctly.
Current implementation:
ctx.accounts.config.protocol_fee_recipient = new_protocol_fee_recipient;
This allows an invalid recipient address to be set, which may cause transactions requiring fee
distribution to fail.
Also the same issue exist in the sboop program in the function update_config
Recommendation
Add a validation check to ensure that new_protocol_fee_recipient is not set to the default public
key:
require!(
 new_protocol_fee_recipient != Pubkey::default(),
 ErrorCode::InvalidProtocolFeeRecipient
);

3.7 Permanent Freezing of create_raydium_pool Due to Seed

Constraint
Description
The create_raydium_pool function is vulnerable to permanent freezing because the pool_state
account is derived from a fixed seed. If the same pool_state is created on Raydium before this
migration, the initialization will fail with the error poolAlreadyCreated , making the function
permanently unusable.
The pool_state account is generated using the following seed constraint:
seeds = [
 POOL_SEED.as_bytes(),
 amm_config.key().as_ref(),
 token_0_mint.key().as_ref(),
 token_1_mint.key().as_ref(),
],
This constraint enforces a deterministic address for the pool, which causes conflicts if the pool has
already been created on Raydium. This issue was prevalent in bonding curves, prompting the Raydium
team to remove this constraint and allow any random account to serve as pool_state , provided it
signs the transaction.
Updated Raydium Implementation
The Raydium team resolved this issue by modifying the constraint, as shown below:
/// CHECK: Initialize an account to store the pool state, init by contract
/// PDA account:
/// seeds = [
///     POOL_SEED.as_bytes(),
///     amm_config.key().as_ref(),
///     token_0_mint.key().as_ref(),
///     token_1_mint.key().as_ref(),
/// ],
///
/// Or random account: must be signed by CLI
#[account(mut)]
pub pool_state: UncheckedAccount<'info>,
Impact
The create_raydium_pool function will be permanently frozen if the same pool has already been
initialized on Raydium.
Recommendation
Remove the seed constraint to allow successful pool initialization. Instead, store the pool address offchain or on-chain as needed.
Updated Implementation
/// CHECK: Initialize an account to store the pool state, init by cp-swap
#[account(mut)]
pub pool_state: UncheckedAccount<'info>,
This approach ensures that the pool creation is not blocked by pre-existing deployments and aligns with
Raydium’s updated methodology.

# Audit B

Findings

1. Medium Findings

1.1. [M-01] Incorrect Handling of Migration Threshold in Buy
Logic
Severity

Impact: Medium
Likelihood: Medium

Description

In the buy logic, after validating slippage, the program checks if there are enough tokens available to be
sold to the user. Additionally, it verifies whether the expected amount to be sold (including the migration
reserve) exceeds the token balance in the bonding curve. If the migration threshold is reached, the
program is supposed to finalize the migration by setting the migration flag to 2 .
However, there is an issue when the condition POOL_MIGRATION_RESERVES + expected_token =
available_token is met. In this case, the logic does not trigger the else branch to set the migration
flag, leaving the migration unfinalized. This oversight creates a vulnerability where tokens can still be
sold, bringing the balance back below the migration threshold after it was reached. This results in a
situation where a subsequent user attempting to buy tokens will receive zero tokens, offering no

incentive for users to trigger the migration flag.

Affected Code
```rust
let (sol_to_spend, token_to_receive, is_finalized) =
 if POOL_MIGRATION_RESERVES + expected_token <= available_token {
 msg!(
 "Pool migration reserves {} + expected_token {} >=
available_token {}",
 POOL_MIGRATION_RESERVES,
 expected_token,
 available_token
 );
 (amount_without_fee, expected_token, false)
 } else {
 msg!("Setting token sale as finalized");
 {
 // here we set the migration flag to 2
 let mut borrowed_data =
token_owner_pda.try_borrow_mut_data().unwrap();
 borrowed_data[0] = 2; // Mark as finalized
 }
 msg!(
 "Pool migration reserves {} + expected_token {} <
available_token {}",
 POOL_MIGRATION_RESERVES,
 expected_token,
 available_token
 );
 // the available to sell is the available token - the migration
reserves
 let token_to_sell = available_token - POOL_MIGRATION_RESERVES;
 // calc the amount of sol corresponding to the token to sell
 let allowed_sol_to_spend = ((pool_sol_balance as u128) *
(token_to_sell as u128)
 / ((pool_token_balance - token_to_sell) as u128))
 as u64;
 msg!(
 "So, amount of sol to spend POST FEE corrected to {}",
 allowed_sol_to_spend
 );
 (allowed_sol_to_spend, token_to_sell, true)
 };
```

Issue

When the condition POOL_MIGRATION_RESERVES + expected_token = available_token holds true,
the else branch is not executed, leaving the migration flag unset. This opens a window for further
token sales and prevents the migration from finalizing correctly.

Recommendations

Update the condition to ensure the migration flag is set when the sum of POOL_MIGRATION_RESERVES

and expected_token equals available_token . Replace the current logic with the following code:

```rust
let (sol_to_spend, token_to_receive, is_finalized) =
 if POOL_MIGRATION_RESERVES + expected_token < available_token {
 msg!(
 "Pool migration reserves {} + expected_token {} <
available_token {}",
 POOL_MIGRATION_RESERVES,
 expected_token,
 available_token
 );
 (amount_without_fee, expected_token, false)
 } else {
 msg!("Setting token sale as finalized");
 {
 // here we set the migration flag to 2
 let mut borrowed_data =
token_owner_pda.try_borrow_mut_data().unwrap();
 borrowed_data[0] = 2; // Mark as finalized
 }
 msg!(
 "Pool migration reserves {} + expected_token {} >=
available_token {}",
 POOL_MIGRATION_RESERVES,
 expected_token,
 available_token
 );
 // the available to sell is the available token - the migration
reserves
 let token_to_sell = available_token - POOL_MIGRATION_RESERVES;
 // calc the amount of sol corresponding to the token to sell
 let allowed_sol_to_spend = ((pool_sol_balance as u128) *
(token_to_sell as u128)
 / ((pool_token_balance - token_to_sell) as u128))
 as u64;
 msg!(
 "So, amount of sol to spend POST FEE corrected to {}",
 allowed_sol_to_spend
 );
 (allowed_sol_to_spend, token_to_sell, true)
 };
```

1.2. [M-02] Prevent Native Tokens from Being Used as Coins

whith the coolpad as the pool creator

Description

Native tokens should not be allowed as coins in the Coolpad program because they cannot be burned,
and the burn functionality is not available for native tokens like SOL. This requires validation to ensure
that if the Coolpad is created, the coin is not native.
According to the SPL token program implementation, attempting to burn a native token will result in an
error in the process_burn function:
```rust
if source_account.is_native() {
 return Err(TokenError::NativeNotSupported.into());
}
```

Impact

Allowing native tokens as coins can lead to a denial-of-service (DoS) scenario where the trading
functionality fails due to the inability to burn native tokens. This would disrupt the expected behavior of
the program.

Recommendation

Prevent Native Tokens from Being Used as Coins whith the coolpad as the pool creator in the function
process_initialize2

3. Low Findings

2.1. [L-01] Missing Use of Checked Math Operations

Description

The code contains multiple instances where standard arithmetic operations are used without checks for
overflow or underflow. This could lead to unintended behavior or vulnerabilities if large values are
involved. Using unchecked operations may result in overflow or underflow, potentially causing incorrect
calculations.

Affected Code

An example of unchecked arithmetic is shown below:
```rust
let expected_token: u64 = ((pool_token_balance as u128) *
(amount_without_fee as u128)
 / ((pool_sol_balance + amount_without_fee) as u128))
 as u64;
```
In the above snippet, arithmetic operations such as multiplication, division, and addition are performed
without safeguards against overflow or underflow. This lack of protection could cause the program to
behave unpredictably if extreme values are encountered.

Recommendations

Use checked math operations such as checked_mul , checked_div , and checked_add to ensure that
arithmetic operations do not result in overflow or underflow. If an overflow or underflow occurs, these
functions return None instead of panicking or silently failing.

The corrected code should look like this:
```rust
let expected_token: u64 = (pool_token_balance as u128)
 .checked_mul(amount_without_fee as u128)
 .and_then(|result| result.checked_div((pool_sol_balance +
amount_without_fee) as u128))
 .unwrap_or_else(|| Err!("Math operation overflow/underflow occurred"))
as u64;
```

2.2. [L-02] Migration Threshold Validation in Sell Token Function

Description

In the process_sell_token function, there is no validation to check whether the migration threshold
has been reached before executing a sell trade. If the POOL_MIGRATION_RESERVES equals or exceeds
the available_token , the migration flag should be set to finalize the token sale. Failing to include this
check can result in unintended behavior, allowing trades to proceed even when the vault is essentially
depleted, and the migration should have been finalized.
Recommendation
Add the following validation before executing the sell trade:
if POOL_MIGRATION_RESERVES >= available_token {
 msg!("Setting token sale as finalized");
 {
 // Set the migration flag to 2
 let mut borrowed_data =
token_owner_pda.try_borrow_mut_data().unwrap();
 borrowed_data[0] = 2; // Mark as finalized
 }
}
This ensures that the migration flag is correctly set if the migration reserve is the only token value
remaining in the vault, preventing further trades and maintaining consistency in the program's state.
2.3. [L-03] Missing Token Program Validation in
process_create_token
Description
In the process_create_token function of the Coolpad program, the migration to Cooldex only accepts
the SPL Token program. However, there is no validation to ensure the provided token program is the
SPL Token program during the creation process.
Recommendation
Add the following check in the process_create_token function:
check_assert_eq!(
 *token_program_info.key,
 spl_token::id(),
 "spl_token_program",
 AmmError::InvalidSplTokenProgram
);
2.4. [L-04] Slippage Protection Broken in Last Trade
Description
During the trading process, the amount of tokens to be sold to the user in the last trade, before setting
the completion flag, can differ from the user's expectations and the slippage parameter they set.
This issue is acknowledged by the developer, as it only affects the last trade. The current
implementation prevents frontrunning of the last trade to ensure the migration flag is not set
prematurely. While this approach works well to prevent frontrunning, it results in broken slippage
protection for the last trade.
let token_to_sell = available_token - POOL_MIGRATION_RESERVES;
The amount of tokens the user receives becomes variable, depending on what is available in the vault.
This prevents the user from accurately setting a slippage protection value.


# AUDIT C

1.1. [C-01] DOS vulnerability because of not Using SOL Amount After

Subtracting Fees in the buy Function

Impact: High

Likelihood: High

Description

In the buy function, the SOL amount provided by the user represents the total amount they want to
pay, including fees. To ensure accurate token distribution, the fees must be subtracted from the SOL
amount before calculating the tokens to be received by the user.
Failure to do so results in incorrect token calculations. Specifically, the tokens sent to the user will
exceed the correct amount, causing the bonding curve to assume a higher SOL reserve than it actually
has. This discrepancy creates a situation where small token sales push the bonding curve into a state
where the new SOL reserve is incorrectly calculated as greater than the current reserve. This can lead
to a revert due to a math error or an overflow when processing small sales.

Impact

This issue results in transaction failures when selling small amounts of tokens and disrupts the proper
functioning of the bonding curve, affecting user experience and the overall stability of the system.

Recommendation

In the calculate_tokens_out function, use the sol_amount after subtracting the fees to accurately
reflect the actual SOL being added to the bonding curve.

Code Fix
```rust
+ let sol_amount_sub_fees = sol_amount.checked_sub(fees).unwrap();
 let tokens_out = calculate_tokens_out(
- sol_amount,
+ sol_amount_sub_fees,
 ctx.accounts.bonding_curve.virtual_sol_reserves
 )?;
```

1.2. [C-02] Vulnerability to Donation Attacks in buy Function

Severity

Impact: High
Likelihood: High

Description

The buy function checks the migration threshold using the account's current_balance , which
includes all SOL in the program account. This approach exposes the protocol to donation attacks,
where an attacker can donate SOL to artificially inflate the balance and prematurely trigger the migration
without completely sell the tokens and distribute them to the users . Once triggered, this prevents token
trading and potentially renders the protocol unusable.

Impact

This vulnerability allows an attacker to manipulate the migration process by triggering it without fully
selling the available tokens. As a result, the token distribution remains incomplete, potentially leading to
user dissatisfaction and loss of trust in the protocol. Additionally, since trading halts once migration is
triggered, the protocol becomes non-operational, directly impacting its utility and revenue generation. In
extreme cases, this could cause a complete shutdown of the protocol's functionality, severely affecting
its users and stakeholders.

Recommendation

To mitigate donation attacks, the buy function should validate the increase in virtual_sol_reserves
independently of the account's current_balance . Use virtual_sol_reserves to track the actual
SOL reserves and update them only with legitimate trades. Replace the migration threshold check logic
as follows:

```rust
 let new_balance = current_balance.checked_add(sol_after_fee)
 .ok_or(ErrorCode::MathError)?;
 //@audit critical donation attacks , we should validate the increase
in the virtual reserves
 if ctx.accounts.bonding_curve.check_migration_threshold(new_balance)
{

ctx.accounts.bonding_curve.update_migration_status(MigrationStatus::Triggere
d)?;
 }
```
we also need to change the function check_migration_threshold to check that the
virtual_sol_reserve is greater than or equal 115 * 1_000_000_000 , this number represent the
initial 30 sol in addition to the 85 sol collected from the bonding curve , appling this fix will prevent
donation attacks since sending sol to the curve will not affect the virtual reserves.

Fix

```rust
fn buy() {
 if
ctx.accounts.bonding_curve.check_migration_threshold(ctx.accounts.bonding_cu
rve.virtual_sol) {

ctx.accounts.bonding_curve.update_migration_status(MigrationStatus::Triggere
d)?;
 }
+ // Use virtual_sol_reserves to validate migration threshold
+ let updated_virtual_reserves =
ctx.accounts.bonding_curve.virtual_sol_reserves
+ .checked_add(sol_after_fee)
+ .ok_or(ErrorCode::Overflow)?;
+ ctx.accounts.bonding_curve.virtual_sol_reserves =
updated_virtual_reserves;
}
 pub fn check_migration_threshold(&self , balance: u64) -> bool {
- balance >= MIGRATION_THRESHOLD
+ self.virtual_sol_reserves >= (115 * 1_000_000_000) // 30 initial SOL
+ 85 SOL from bonding curve
 }
```

1.3. [C-03] Freeze Authority Enabled on Mint Prevents Raydium Pool

Creation
Severity
Impact: High
Likelihood: High

Description

In the create function, the mint account is initialized with its freeze authority set to the mint authority:

```rust
pub struct Create<'info> {
 #[account(
 init,
 payer = payer,
 mint::decimals = 6,
 mint::authority = mint_authority,
 mint::freeze_authority = mint_authority
 )]
 pub mint: Account<'info, Mint>,
}
```

According to the Raydium documentation SPL tokens must have the freeze authority feature disabled
for a liquidity pool to be created. Enabling freeze authority prevents migration to Raydium and the
creation of liquidity pools pairing these tokens.

This issue will have a critical impact on the protocol, as it will permanently block migration to Raydium
and render the protocol unusable. Additionally, all funds collected for this purpose will remain locked,
leading to a complete failure in achieving the protocol's objectives.

Recommendations

Disable the freeze authority when initializing the mint account.

Recommended Implementation

```rust pub struct Create<'info> {
 #[account(
 init,
 payer = payer,
 mint::decimals = 6,
 mint::authority = mint_authority,
- mint::freeze_authority = mint_authority
 )]
 pub mint: Account<'info, Mint>,
}
```

1.4. [C-04] Slippage Validation Against Unscaled Token Output
Severity
Impact: High
Likelihood: High

Description

The buy function contains a critical flaw in the slippage validation logic. The slippage parameter
( min_token_amount ) is intended to protect users by ensuring the trade results in a minimum
acceptable amount of tokens. However, this parameter is validated against the unscaled tokens_out
value, which does not account for the token's decimal scaling (6 decimals in this case). Since the
slippage parameter represents the token amount with 6 decimals, comparing it against the unscaled
value renders the validation logic invalid.
This issue allows trades to proceed with prices outside the acceptable slippage range, leading to a
potential loss of funds for users.

Affected Code

```rust
pub fn buy(ctx: Context<Buy>, sol_amount: u64, min_token_amount: u64) ->
Result<()> {
 let tokens_out = calculate_tokens_out(
 sol_amount,
 ctx.accounts.bonding_curve.virtual_sol_reserves
 )?;
 msg!("Calculated tokens_out: {}", tokens_out);
 // Check min tokens
 require!(tokens_out >= min_token_amount, ErrorCode::ExcessiveSlippage);
 let scaled_virtual_tokens = tokens_out.checked_mul(1_000_000)
 .ok_or_else(|| {
 msg!("Error scaling tokens_out");
 ErrorCode::Overflow
 })?;
 msg!("Scaled virtual tokens: {}", scaled_virtual_tokens);
}
```

Impact

Invalid slippage validation allows users to execute trades at unintended prices.
This can result in significant financial losses for users, undermining the protocol's reliability and
security.

Recommendation

To ensure proper slippage validation, compare the min_token_amount parameter against the scaled
token output ( scaled_virtual_tokens ) rather than the unscaled value. Update the validation logic as
follows:

```rust require!(scaled_virtual_tokens >= min_token_amount,
ErrorCode::ExcessiveSlippage);
```

2. High Findings

2.1. [H-01] Migration Flag Not Triggered After Buy Trade
Severity

Impact: High
Likelihood: Medium

Description

In the current implementation of the buy function, the migration threshold is checked before the
bonding curve is updated. This leads to a situation where a buy trade can result in a token amount that
exceeds the migration limit, but the migration flag will not be set. Consequently, the trading will continue
even though the migration threshold has been surpassed.
For instance, if the current state of the curve results in 84 SOL in funds, and the trade pushes this to 86
SOL, the migration should be triggered. However, since the flag is set before the trade, the migration
will not be initiated, which could leave the system in an inconsistent state.
The current implementation does not account for the updated reserves post-trade, which would impact
whether the migration threshold has been exceeded.

Recommendations

To fix this issue, the migration threshold check should occur after the buy transaction has been
completed, ensuring that the migration flag is set based on the updated reserves. This way, if the
migration threshold is met after the trade, the flag will be correctly triggered, stopping further trading as
expected.

Here’s the updated implementation:

```rust
pub fn buy(ctx: Context<Buy>, sol_amount: u64, min_token_amount: u64) ->
Result<()> {
 msg!("Starting buy operation with {} sol", sol_amount);
 msg!("Current virtual_sol_reserves: {}",
ctx.accounts.bonding_curve.virtual_sol_reserves);
 msg!("Current virtual_token_reserves: {}",
ctx.accounts.bonding_curve.virtual_token_reserves);
 // Check flag to ensure program is not paused
 require!(!ctx.accounts.bonding_curve.is_paused(),
ErrorCode::ProgramPaused);

ctx.accounts.bonding_curve.log_migration_state(&ctx.accounts.bonding_curve.t
o_account_info());
 // Make sure the migration is not in progress
 require!(
 ctx.accounts.bonding_curve.can_trade(),
 ErrorCode::MigrationInProgress
 );
 // Perform the buy operation and calculate tokens out
 let tokens_out = calculate_tokens_out(
 sol_amount,
 ctx.accounts.bonding_curve.virtual_sol_reserves
 )?;
 msg!("Calculated tokens_out: {}", tokens_out);
 // Update reserves based on the trade
 // Check migration threshold AFTER the trade
 if
ctx.accounts.bonding_curve.check_migration_threshold(ctx.accounts.bonding_cu
rve.virtual_sol_reserves) {

ctx.accounts.bonding_curve.update_migration_status(MigrationStatus::Triggere
d)?;
 }
 // Ensure the user gets the expected amount of tokens (minimum check)
 require!(tokens_out >= min_token_amount,
ErrorCode::InsufficientOutputAmount);
 Ok(())
}
```

Key Changes:

The migration threshold check is moved after the buy operation to ensure that the updated state of
the reserves is considered when evaluating whether migration should be triggered.
Reserves are updated after the buy operation, ensuring that the new balance reflects the trade’s
impact before triggering the migration flag.


2.2. [H-02] Unprotected Pool Creation in Raydium Migration Process

Severity
Impact: High
Likelihood: Medium

Description

The current implementation of the migration process from the existing AMM to Raydium's Pools is
vulnerable to a race condition that could allow an attacker to block the migration.
The proxy_initialize function attempts to create a new pool in Raydium and force the pool_state
account to be driven from this seed

```rust  seeds = [
 POOL_SEED.as_bytes(),
 amm_config.key().as_ref(),
 token_0_mint.key().as_ref(),
 token_1_mint.key().as_ref(),
 ],
 seeds::program = cp_swap_program,
```

This creates a window of opportunity for an attacker to preemptively create the same pool in Raydium,
effectively blocking the official migration process.

The vulnerability's two main factors:

1. Lack of Pre-existence Check: The migration code does not verify whether a pool with the same
tokens and AMM config already exists in Raydium before attempting to create one.

3. No Exclusive Creation Rights: There's no mechanism to ensure that only the official migration
process can create the new pool in Raydium.

Raydium Team has addressed this issue and allowed the pool state to be an arbitrary address , but it
should sign the tx by cli as per docs here
```rust
 /// CHECK: Initialize an account to store the pool state
 /// PDA account:
 /// seeds = [
 ///     POOL_SEED.as_bytes(),
 ///     amm_config.key().as_ref(),
 ///     token_0_mint.key().as_ref(),
 ///     token_1_mint.key().as_ref(),
 /// ],
 ///
 /// Or random account: must be signed by cli
 #[account(mut)]
 pub pool_state: UncheckedAccount<'info>,
A "Pool already created" error could occur if you try to initialize a pool that was already initialized.
https://docs.raydium.io/raydium/pool-creation-faq#pool-already-created-error
```
Impact
This vulnerability will lead to permanent DOS to the migration process.

Recommendations

```rust
 #[account(
 mut,
- seeds = [
- POOL_SEED.as_bytes(),
- amm_config.key().as_ref(),
- token_0_mint.key().as_ref(),
- token_1_mint.key().as_ref(),
- ],
- seeds::program = cp_swap_program,
- bump,
 )]
 pub pool_state: UncheckedAccount<'info>,
```
remove those seeds contraints to allow pool initialization at any random address.


2.3. [H-03] Unauthorized Fee Token Account in the finalize_migration
Function
Severity
Impact: High
Likelihood: Medium
Description

In the finalize_migration function, the fee_token_account is defined as follows:
```rust
/// CHECK: Will be initialized if needed
#[account(mut)]
pub fee_token_account: AccountInfo<'info>,
```
The fee_token_account is not properly validated, and since this function is permissionless, it allows
an attacker to set this account to a malicious address. This could potentially enable unauthorized
transfers or other malicious activities involving the fee tokens.

Recommendations

To prevent such attacks, the fee_token_account should be validated similarly to how it is done in the
emergency_withdraw function. Use the following pattern to ensure proper validation:
```rust
#[account(
 init_if_needed,
 payer = authority,
 associated_token::mint = mint,
 associated_token::authority = fee_account
)]
pub fee_token_account: Account<'info, TokenAccount>,
```
This approach ensures the fee_token_account is securely initialized and tied to the correct mint and
authority, mitigating the risk of unauthorized access.

You also need to add the payer account to the list of the accounts .

3. Medium Findings
4. 
3.1. [M-01] Bonding Curve Exceeds Migration Threshold
Severity
Impact: Medium
Likelihood: Medium

Description

The available_sol_amount function needs to be added to ensure that the amount of SOL traded
during the migration does not exceed the predefined migration threshold of 85 SOL. Without this
validation, it is possible for the bonding curve to receive more SOL than intended, leading to undesired
protocol behavior or potential fund mismanagement. 
This function calculates the remaining amount of
SOL that can be traded by comparing the migration_threshold with the current
virtual_sol_reserve .
If the remaining amount is less than the user's intended sol_amount , the
trade is capped at the remaining amount. The logic can be expressed as follows:
```rust
fn available_sol_amount(sol_amount: u64, virtual_sol_reserve: u64,
migration_threshold: u64, sol_amount_sub_fees: u64) -> u64 {
 let remaining = migration_threshold.saturating_sub(virtual_sol_reserve);
 std::cmp::min(sol_amount_sub_fees, remaining)
}
```
This function should be invoked before calculating the tokens_out to ensure the bonding curve
remains within the migration threshold. Below is an example of how to incorporate it:

```rust
let sol_amount = available_sol_amount(
 user_sol_amount,
 ctx.accounts.bonding_curve.virtual_sol_reserves,
 migration_threshold,
 sol_amount_sub_fees
);
let tokens_out = calculate_tokens_out(
 sol_amount,
 ctx.accounts.bonding_curve.virtual_sol_reserves
)?;
msg!("Calculated tokens_out: {}", tokens_out);
```
This adjustment prevents the bonding curve from exceeding the migration threshold, maintaining
protocol integrity and ensuring proper fund allocation.

Recommendations

1. Integrate the available_sol_amount function into the migration logic to cap SOL trades at the
migration threshold.


3.2. [M-02] Slippage Validation Performed on Gross Output Instead of Net
Output
Severity
Impact: Medium
Likelihood: Medium

Description

The min_sol_output parameter is designed to protect users from excessive slippage by ensuring that
the trade price is acceptable. However, in the current implementation, the slippage check is performed
on the gross output (the amount before subtracting fees) rather than the net output (the amount the
user will actually receive after fees).

This introduces a vulnerability, as users may receive less SOL than expected, especially when fees are
significant. For example, the gross output could meet the min_sol_output threshold, but the actual
amount received (net output) may fall below the acceptable level due to fees.

Relevant Code
```rust
let sol_output = calculate_sol_output(
 token_amount,
 ctx.accounts.bonding_curve.virtual_sol_reserves,
 ctx.accounts.bonding_curve.virtual_token_reserves
)?;
msg!("SOL output: {}", sol_output);
// Check min output
msg!("Check min output SOL {} >= {}", sol_output, min_sol_output);
// @audit high vulnerability: the slippage should be applied on the amount
that the user will receive (net output), not the gross output
require!(sol_output >= min_sol_output, ErrorCode::ExcessiveSlippage);
// Calculate fee
let fee = sol_output.checked_mul(FEE_NUMERATOR)
 .ok_or(ErrorCode::MathError)?
 .checked_div(FEE_DENOMINATOR)
 .ok_or_else(|| {
 msg!("Failed to calculate fee from {}", sol_output);
 ErrorCode::MathError
 })?;
msg!("Fee (1.5%): {}", fee);
// Calculate net output
let net_output = sol_output.checked_sub(fee)
 .ok_or_else(|| {
 msg!("Failed to subtract fee {} from {}", fee, sol_output);
 ErrorCode::MathError
 })?;
msg!("Net output: {}", net_output);
```
Impact

This issue can result in loss of funds for users, as trades may execute at unintended prices, violating
their acceptable slippage settings.

Recommendations

Update the implementation to validate the min_sol_output parameter against the net output value
(the amount of SOL received after fees are deducted).

Recommended Implementation

```rust
let sol_output = calculate_sol_output(
 token_amount,
 ctx.accounts.bonding_curve.virtual_sol_reserves,
 ctx.accounts.bonding_curve.virtual_token_reserves
)?;
msg!("SOL output: {}", sol_output);
// Calculate fee
let fee = sol_output.checked_mul(FEE_NUMERATOR)
 .ok_or(ErrorCode::MathError)?
 .checked_div(FEE_DENOMINATOR)
 .ok_or_else(|| {
 msg!("Failed to calculate fee from {}", sol_output);
 ErrorCode::MathError
 })?;
msg!("Fee (1.5%): {}", fee);
// Calculate net output
let net_output = sol_output.checked_sub(fee)
 .ok_or_else(|| {
 msg!("Failed to subtract fee {} from {}", fee, sol_output);
 ErrorCode::MathError
 })?;
msg!("Net output: {}", net_output);
// Check min output against net output
msg!("Check min output SOL {} >= {}", net_output, min_sol_output);
require!(net_output >= min_sol_output, ErrorCode::ExcessiveSlippage);
```
Key Benefits of This Fix

Ensures users receive at least the expected amount of SOL after fees, honoring their slippage  settings.

# Audit D


[C-01] Sending PC tokens directly to pool_pc_token account

leads to DOS
Severity
Impact: High
Likelihood: High

Description

Consider a scenario where the pool has successfully sold most of its PC tokens and accumulated a
significant amount of WSOL. At this point, the reserve ratio stands at 30,000,000 :
100,000,000,000 . A malicious user who initially purchased 30,000,000 PC tokens at a low price
during the early stages of the bonding curve can exploit this situation.

The first 30_000_000 will cost 1.387 Sol , which is a very low cost for the malicious user.
This malicious user can send those tokens directly to the pool_pc_account without initiating a swap.
As a result, the following check in the migration function will always fail:

let pool_pc_balance = ctx.accounts.pool_token_pc.amount;

const MAX_POOL_PC_BALANCE: u64 = 30_000_000 * (10u64.pow(6));

assert!(pool_pc_balance < MAX_POOL_PC_BALANCE, "Migration can only happen

when only 30mm tokens are left in the pool.");

Because the pool uses internal accounting for swaps, this donation of tokens does not affect the price

or the reserve ratio. The reserve ratio remains unchanged, as shown in the swap logic:
```rust
let a_reserves = ctx.accounts.pool.reserves_a;
let b_reserves = ctx.accounts.pool.reserves_b;
let output: u64 = if swap_a {
 ((input as u128) * (b_reserves as u128))
 .checked_div((a_reserves as u128) + (input as u128))
 .ok_or(BondingCurveError::Overflow)? as u64
} else {
 ((input as u128) * (a_reserves as u128))
 .checked_div((b_reserves as u128) + (input as u128))
 .ok_or(BondingCurveError::Overflow)? as u64
};
```
Since the constant product market maker (CPMM) mechanism makes it impossible to swap out the
entire token reserve, it becomes impossible to resume the migration. The migration function expects a
transfer of 30,000,000 PC tokens, which is now blocked due to the inflated token balance. This results
in a permanent and unrecoverable denial of service (DoS) to the migration process.
This issue can occur with various reserve ratios and only requires a donation of PC tokens, making
swaps of the pc_amount that will make the pool_pc_balance lower than the MAX_POOL_PC_BALANCE
prohibitively expensive or even impossible.

Recommendation

To prevent this manipulation, the check for the maximum pool PC balance should compare against
pool.reserves_b instead of the actual balance of the pool. This change will ensure that token
donations do not interfere with the migration process and prevent a denial of service.

let pool_pc_balance = pool.reserves_a;
const MAX_POOL_PC_BALANCE: u64 = 30_000_000 * (10u64.pow(6));
assert!(pool_pc_balance < MAX_POOL_PC_BALANCE, "Migration can only happen
when only 30mm tokens are left in the pool.");

[M-01] Lack of trading pause after migration
Severity
Impact: Medium
Likelihood: Medium

Description

In the migrate_cpmm function, after a successful migration, trading is not paused. This creates a
vulnerability where any assets left in the pool can be permanently locked. Since the pool is not designed
to allow token withdrawal after migration and only allows swapping, any assets that will be traded in the
pool will be inaccessible to users, leading to a permanent lock of funds for those attempting to swap
after the migration.

Current migration function:

```rust
pub fn migrate_cpmm(
 ctx: Context<MigrateCPMM>,
) -> Result<()> {
 assert_eq!(ctx.accounts.pool.complete, true);
 assert_eq!(ctx.accounts.payer.key(), ctx.accounts.amm.migrator);
 ...
 let cpi_accounts = Burn {
 mint: ctx.accounts.amm_lp_mint.to_account_info(),
 from: ctx.accounts.user_token_lp.to_account_info(),
 authority: ctx.accounts.payer.to_account_info(),
 };
 let cpi_ctx: CpiContext<Burn> =
CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
 token::burn(cpi_ctx, amount)?;
 Ok(())
}
```

If trading is not paused after migration, funds that remain in the pool post-migration will become
permanently locked. This issue can lead to significant financial losses for users who try to swap after
migration, as there will be no mechanism to withdraw funds from the pool.

Recommendations

1. Pause trading after migration: Add a flag to the pool structure, such as pool.trade_paused , and
set it to true after the migration process is complete. This flag should be checked on every trade
attempt to prevent further swaps after migration.
2. Allow withdrawal after migration: Implement a mechanism to allow users to withdraw their funds
from the pool after the migration, ensuring that no assets are permanently locked.

Example modification:

```rust
pub fn migrate_cpmm(
 ctx: Context<MigrateCPMM>,
) -> Result<()> {
 assert_eq!(ctx.accounts.pool.complete, true);
 assert_eq!(ctx.accounts.payer.key(), ctx.accounts.amm.migrator);
 // Pause trading after migration
 ctx.accounts.pool.trade_paused = true;
 let cpi_accounts = Burn {
 mint: ctx.accounts.amm_lp_mint.to_account_info(),
 from: ctx.accounts.user_token_lp.to_account_info(),
 authority: ctx.accounts.payer.to_account_info(),
 };
 let cpi_ctx: CpiContext<Burn> =
CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
 token::burn(cpi_ctx, amount)?;
 Ok(())
}
```
This ensures that the pool is no longer usable for trading after migration and prevents funds from
becoming inaccessible.

[M-02] Pool balance manipulation before migration

Severity
Impact: Medium
Likelihood: Medium

Description

In the migrate_cpmm function, the pool migration is restricted by a maximum pool balance limit of 30
million pc tokens, as shown in the following snippet:

let pool_pc_balance = ctx.accounts.pool_token_pc.amount;
assert!(pool_pc_balance < MAX_POOL_PC_BALANCE, "Migration can only happen
when only 30mm tokens are left in the pool.");

A malicious user can exploit this by observing the upcoming migration transaction and swapping pc
tokens for coin to artificially increase the balance of pool_token_pc . By doing so, they can cause the
pool_pc_balance to exceed the 30 million token limit, resulting in the migration transaction failing.
This can disrupt the migration process and delay or prevent the protocol from completing the migration.
Successful exploitation of this vulnerability can block the migration of the bonding curve to the Raydium
AMM. This could lead to prolonged downtime, affecting liquidity and user trust. If such attacks are
performed repeatedly, it could also create a denial-of-service (DoS) scenario for the migration process.

Recommendations

Pause trading When the migration goal is reached:
When the migration process is triggered and the balance is about to reach the target limit (30 million
pc tokens or less), all trading on the pool should be paused immediately. This will prevent further
swaps from artificially inflating the pool balance during the migration process.


[M-03] Migration to Raydium fails for pools with tokens having
freeze authority enabled
Severity
Impact: Medium
Likelihood: Medium

Description

The Dub allows for the creation of pools with tokens that may have freeze authority enabled. However,
the migration process to Raydium requires that all tokens in the pool have their freeze authority
disabled. This mismatch creates a critical issue where migration attempts for pools containing tokens
with enabled freeze authority will fail.

```rust
raydium_cp_swap::cpi::initialize(
 cpi_ctx,
 token_0_amount,
 token_1_amount,
 0,
 )?;
 }
```
bonding-curve/src/instructions/migrate_cpmm.rs:L14

As a result, migrators attempting to migrate their liquidity from pools containing tokens with enabled
freeze authority will experience failed transactions which leads to user funds becoming stuck in Dub
pool.

The issue affects all pools created in Dub protocol that contain tokens with enabled freeze authority,
potentially impacting a significant portion of pools and users.

References:

https://docs.raydium.io/raydium/pool-creation/creating-a-constant-product-pool

Recommendations

Add a check to ensure the tokens doesn't have an active freeze authority. If you still want to support a
few tokens that have active freeze authority, consider migrating these pools to an alternative DEX.


[M-04] Freeze authority on base mint in deploy_bonding_mint

Severity
Impact: Medium
Likelihood: Medium

Description For SPL tokens, pool creation requires freeze authority disabled
In the deploy_bonding_mint function, the base_mint of the pool is set, and the mint is initialized.
However, there is no check to verify whether the freeze_authority of the base_mint token is set. If
the freeze_authority is assigned to a public key, the account holding this authority can freeze critical
token accounts, such as the fee_vault , which is used during swaps to collect fees. This would result
in a permanent denial of service (DOS) on the swapping functionality for all AMMs relying on this
bonding curve.

Here is the relevant portion of the deploy_bonding_mint function:

```rust
#[account(
 init,
 payer = payer,
 seeds = [
 amm.key().as_ref(),
 mint_bump.key().as_ref()
 ],
 bump,
 mint::decimals = 6,
 mint::authority = amm_authority
)]
pub mint: Box<Account<'info, Mint>>,
// #[account]
/// CHECK:
pub mint_base: AccountInfo<'info>,
```
During the swap process, a fee is calculated and sent to the fee_vault . If the fee_vault is frozen
due to an unchecked freeze_authority , it would prevent swaps, as shown below in the
swap_exact_tokens_for_tokens function:

```rust
let tax = input_pretax * amm.fee as u64 / 10000;
token::transfer(
 CpiContext::new(
 ctx.accounts.token_program.to_account_info(),
 Transfer {
 from: ctx.accounts.trader_account_a.to_account_info(),
 to: ctx.accounts.fee_vault_token_account.to_account_info(),
 authority: ctx.accounts.trader.to_account_info(),
 },
 ),
 tax,
)?;
```
This freeze could render the entire AMM system unusable, as no trades could be processed due to the
inability to transfer fees.
If the freeze_authority of the base_mint is exploited or utilized, it could cause a permanent DOS
on the swapping functionality, making the bonding curve and its AMM useless. Without safeguards, any
malicious or compromised actor with the freeze_authority could disrupt the AMM operations.
Also migrators will not be able to migrate their liquidity from pools due to the migration goal did not get
reached , which leads to user funds becoming stuck in Dub pool.

Recommendation

1. Check for freeze_authority : Ensure that the base_mint does not have a freeze_authority
set, or that it is handled carefully. An example of the check could be:

if mint_account.freeze_authority.is_some() {
 return Err(Error::MintHasFreezeAuthority);
}

3. Display Warnings for Tokens with freeze_authority : If supporting tokens with a
freeze_authority is necessary, display a warning to users in the UI, informing them of the risks
associated with trading or interacting with these tokens.

5. Implement Allowlist for Trusted Tokens: For regulated stablecoins like USDC, which have a
freeze_authority for security reasons, implement an allowlist for trusted tokens while applying
strict checks on other tokens.
This ensures the protocol can support widely-used tokens while
minimizing risk.
By applying these changes, the protocol will mitigate the risk of an unexpected DOS due to the freezing
of critical token accounts.

[M-05] Premature token releases in Lock program
Severity
Impact: Medium
Likelihood: Medium

Description

The handle_release function in release.rs lacks proper time-based checks and validation of
unlock criteria before setting claim_approved to true . This could allow premature token releases,
potentially enabling attacks using flash loans to unlock and dump tokens before their intended vesting
date.

```rust

// Check if the unlock criteria have been met
 match lockbox.unlock_criteria {
 UnlockCriteria::None => {
 // No specific criteria, always allow release
 },
 UnlockCriteria::BondingPrice { .. } => {
 // let current_time = Clock::get()?.unix_timestamp;
 // require!(current_time >= unlock_time,
ErrorCode::UnlockConditionsNotMet);
 // TODO
 },
 UnlockCriteria::RaydiumPrice { .. } => {
 // Price-based criteria should be checked elsewhere, possibly
off-chain
 // Here we assume it's already verified if this criteria is set
 },
 }
 // Set claim_approved to true
 lockbox.claim_approved = true;
lock/src/instructions/release.rs:L42
```

Recommendations

Update handle_release to include Time-based checks ensuring current timestamp ≥ scheduled
unlock time. Or Implement a proper validation of specified unlock criteria (e.g., bonding price
thresholds).

[M-06] State inconsistency due to Solana rollback

Severity
Impact: Medium
Likelihood: Medium

Description

Two critical functions in the protocol are vulnerable to state inconsistencies in the event of a Solana
rollback:
Merkle Root Updates: The handle_update_root function in
merkle_distributor/update_root.rs updates the Merkle root, max claim amounts, and resets
claim counters. A rollback after this update could create a mismatch between off-chain data and onchain state, potentially allowing unintended claims, exceeding claim limits, or enabling doubleclaiming.

AMM Pause Mechanism: the update_pause function in bonding_curve/update.rs controls the
AMM's ability to halt trading in emergency situations. However, in the event of a Solana rollback,
this critical security feature could be compromised. If the AMM was paused due to a detected
security threat, a rollback could revert it to an active state, potentially exposing the protocol to the
very threat it was trying to mitigate.

Recommendations

Utilize the LastRestartSlot sysvar to detect outdated configuration states. If the config is outdated,
the protocol should automatically pause until an action is taken by the admin.

Example as an inspiration:

```rust
Add a last_updated_slot field to the AMM state struct:
pub struct AmmState {
 // ... other fields ...
 pub last_updated_slot: u64,
 pub trading_paused: bool,
 // ... other fields ...
}
```
```rust
Add a function to check if the config is outdated:
fn is_config_outdated(amm_state: &AmmState) -> Result<bool> {
 let last_restart_slot = LastRestartSlot::get()?;
 Ok(amm_state.last_updated_slot <=
last_restart_slot.last_restart_slot)
}
```

Modify the swap_exact_tokens_for_tokens and other critical functions to check for outdated
config

```rust
pub fn swap_exact_tokens_for_tokens(ctx:
Context<SwapExactTokensForTokens>, ...) -> Result<()> {
 let amm = &ctx.accounts.amm;
 if is_config_outdated(amm)? || amm.trading_paused {
 return err!(BondingCurveError::TradingPaused);
 }
 // ... rest of the function
}
```
Update the last_updated_slot in the update_pause function

```rust
pub fn update_pause(ctx: Context<UpdatePause>, new_pause: bool) ->
Result<()> {
 require!(ctx.accounts.admin.key() == ctx.accounts.amm.admin,
BondingCurveError::Unauthorized);
 let amm = &mut ctx.accounts.amm;
 amm.trading_paused = new_pause;
 amm.last_updated_slot = Clock::get()?.slot;
 Ok(())
}
```

[M-07] DoS for legitimate AMM creators is possible

Severity
Impact: Medium
Likelihood: Medium

Description

create_amm function in bonding curve is vulnerable to front-running attacks.
A scenario of how this could occur:

A legitimate user submits a transaction to create an AMM with a specific ID.
The attacker quickly submits their own transaction to create an AMM with the same ID, but with
higher gas fees.

The attacker's transaction is processed first, creating the AMM with the attacker's parameters.
The legitimate user's transaction fails due to the AMM ID already being in use.

This could lead to:

DoS for legitimate AMM creators
Creation of malicious AMMs that mimic legitimate ones
The current code doesn't have any mechanism to prevent this type of attack:

```rust
#[derive(Accounts)]
#[instruction(id: Pubkey, fee: u16)]
pub struct CreateAmm<'info> {
 #[account(
 init,
 payer = payer,
 space = Amm::LEN,
 seeds = [id.as_ref()],
 bump,
 constraint = fee < 30000 @ BondingCurveError::InvalidFee,
 )]
 pub amm: Box<Account<'info, Amm>>,
 // ... other fields
}
```
bonding-curve/src/instructions/create_amm.rs:L42

The AMM is created using only the provided id .

Recommendations

To mitigate this, I recommend implementing a sequential numbering. This can be achieved by:
Adding a new account to store the latest AMM sequence number.
Modifying the CreateAmm struct and create_amm function to use this sequence number.
Here's a proposed implementation:

```rust
#[derive(Accounts)]
#[instruction(id: Pubkey, fee: u16)]
pub struct CreateAmm<'info> {
 #[account(
 init,
 payer = payer,
 space = Amm::LEN,
 seeds = [id.as_ref(),
amm_sequence.current_sequence.to_le_bytes().as_ref()],
 bump,
 constraint = fee < 30000 @ BondingCurveError::InvalidFee,
 )]
 pub amm: Box<Account<'info, Amm>>,
 #[account(mut)]
 pub amm_sequence: Account<'info, AmmSequence>,
 // ... other fields
}
#[account]
pub struct AmmSequence {
 pub current_sequence: u64,
}
pub fn create_amm(ctx: Context<CreateAmm>, /* ... other params */) ->
Result<()> {
 // ... existing code
 // Increment and use the sequence number
 ctx.accounts.amm_sequence.current_sequence += 1;
 ctx.accounts.amm.sequence = ctx.accounts.amm_sequence.current_sequence;
 // ... rest of the function
}
```
Please make sure that the AmmSequence account can only be modified by the program itself.

[M-08] Fee rounding enables zero-fee swaps

Severity
Impact: Medium
Likelihood: Medium

Description

In the current swap fee calculation, fees are rounded down, which can result in zero fees being applied
when swapping small amounts of low decimal tokens. This is particularly problematic for tokens with a
low decimal precision (e.g., 3 decimals). For example, if the fee is set at 1% (or 100 basis points) and
the amount to swap is 99 , no fee is applied, effectively allowing a user to swap tokens for free. In the
case of low decimal tokens, a user could repeatedly swap small amounts without incurring any fees.

As shown in the following snippet, the fee is calculated by dividing input_pretax * amm.fee by
10000 :
let tax = input_pretax * amm.fee as u64 / 10000;
The issue arises because the division rounds down, which results in 0 for small input amounts.
This test case demonstrates how the current fee calculation can round down to zero:
```rust
#[test]
fn test_fee_rounding_down(){
 let fee = 100; // 1.00% fee
 let input_pretax = 99;
 let tax = input_pretax * fee as u64 / 10000;
 let input_amount_post_fee = input_pretax - tax;
 println!("fee amount: {:?}", tax);
 println!("input amount post fee: {:?}", input_amount_post_fee);
 // logs:
 // fee amount : 0
 // input amount post fee 99
}
```

In this example, the fee amount is calculated as 0 , meaning the swap proceeds without any fee. This
issue could be exploited by swapping 99 units of a low decimal token repeatedly to avoid paying fees.
This issue allows users to swap certain token amounts without incurring fees, particularly for low
decimal tokens. This can be exploited, leading to potential revenue loss for the protocol and
undermining the fee structure of the bonding curve.

Recommendation

To prevent the fee from rounding down to zero, use a ceiling division ( ceil_div ) instead of a standard
division ( / ), ensuring that the fee is always rounded up
```rust
or this can be used :
let tax = input_pretax * amm.fee as u64
 .checked_add(9999) // Add this to round up when dividing
 .ok_or(BondingCurveError::Overflow)?
 / 10000;
```
This change will ensure that even for small amounts of tokens, a non-zero fee will be taken, preventing
users from bypassing the fee system.


# AUDIT E

[C-01] Sending PC tokens directly to pool_pc_token account

leads to DOS
Severity
Impact: High
Likelihood: High

Description

Consider a scenario where the pool has successfully sold most of its PC tokens and accumulated a
significant amount of WSOL. At this point, the reserve ratio stands at 30,000,000 :

100,000,000,000 . A malicious user who initially purchased 30,000,000 PC tokens at a low price
during the early stages of the bonding curve can exploit this situation.

The first 30_000_000 will cost 1.387 Sol , which is a very low cost for the malicious user.
This malicious user can send those tokens directly to the pool_pc_account without initiating a swap.
As a result, the following check in the migration function will always fail:

let pool_pc_balance = ctx.accounts.pool_token_pc.amount;

const MAX_POOL_PC_BALANCE: u64 = 30_000_000 * (10u64.pow(6));

assert!(pool_pc_balance < MAX_POOL_PC_BALANCE, "Migration can only happen

when only 30mm tokens are left in the pool.");

Because the pool uses internal accounting for swaps, this donation of tokens does not affect the price
or the reserve ratio. The reserve ratio remains unchanged, as shown in the swap logic:

```rust
let a_reserves = ctx.accounts.pool.reserves_a;
let b_reserves = ctx.accounts.pool.reserves_b;
let output: u64 = if swap_a {
 ((input as u128) * (b_reserves as u128))
 .checked_div((a_reserves as u128) + (input as u128))
 .ok_or(BondingCurveError::Overflow)? as u64
} else {
 ((input as u128) * (a_reserves as u128))
 .checked_div((b_reserves as u128) + (input as u128))
 .ok_or(BondingCurveError::Overflow)? as u64
};
```

Since the constant product market maker (CPMM) mechanism makes it impossible to swap out the
entire token reserve, it becomes impossible to resume the migration. The migration function expects a
transfer of 30,000,000 PC tokens, which is now blocked due to the inflated token balance. This results
in a permanent and unrecoverable denial of service (DoS) to the migration process.
This issue can occur with various reserve ratios and only requires a donation of PC tokens, making
swaps of the pc_amount that will make the pool_pc_balance lower than the MAX_POOL_PC_BALANCE
prohibitively expensive or even impossible.

Recommendation

To prevent this manipulation, the check for the maximum pool PC balance should compare against
pool.reserves_b instead of the actual balance of the pool. This change will ensure that token
donations do not interfere with the migration process and prevent a denial of service.

let pool_pc_balance = pool.reserves_a;
const MAX_POOL_PC_BALANCE: u64 = 30_000_000 * (10u64.pow(6));
assert!(pool_pc_balance < MAX_POOL_PC_BALANCE, "Migration can only happen
when only 30mm tokens are left in the pool.");

[M-01] Lack of trading pause after migration
Severity

Impact: Medium
Likelihood: Medium

Description

In the migrate_cpmm function, after a successful migration, trading is not paused. This creates a
vulnerability where any assets left in the pool can be permanently locked. Since the pool is not designed
to allow token withdrawal after migration and only allows swapping, any assets that will be traded in the
pool will be inaccessible to users, leading to a permanent lock of funds for those attempting to swap
after the migration.

Current migration function:

```rust
pub fn migrate_cpmm(
 ctx: Context<MigrateCPMM>,
) -> Result<()> {
 assert_eq!(ctx.accounts.pool.complete, true);
 assert_eq!(ctx.accounts.payer.key(), ctx.accounts.amm.migrator);
 ...
 let cpi_accounts = Burn {
 mint: ctx.accounts.amm_lp_mint.to_account_info(),
 from: ctx.accounts.user_token_lp.to_account_info(),
 authority: ctx.accounts.payer.to_account_info(),
 };
 let cpi_ctx: CpiContext<Burn> =
CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
 token::burn(cpi_ctx, amount)?;
 Ok(())
}
```
If trading is not paused after migration, funds that remain in the pool post-migration will become
permanently locked. This issue can lead to significant financial losses for users who try to swap after
migration, as there will be no mechanism to withdraw funds from the pool.

Recommendations

1. Pause trading after migration: Add a flag to the pool structure, such as pool.trade_paused , and
set it to true after the migration process is complete. This flag should be checked on every trade
attempt to prevent further swaps after migration.

3. Allow withdrawal after migration: Implement a mechanism to allow users to withdraw their funds
from the pool after the migration, ensuring that no assets are permanently locked.

Example modification:

```rust
pub fn migrate_cpmm(
 ctx: Context<MigrateCPMM>,
) -> Result<()> {
 assert_eq!(ctx.accounts.pool.complete, true);
 assert_eq!(ctx.accounts.payer.key(), ctx.accounts.amm.migrator);
 // Pause trading after migration
 ctx.accounts.pool.trade_paused = true;
 let cpi_accounts = Burn {
 mint: ctx.accounts.amm_lp_mint.to_account_info(),
 from: ctx.accounts.user_token_lp.to_account_info(),
 authority: ctx.accounts.payer.to_account_info(),
 };
 let cpi_ctx: CpiContext<Burn> =
CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
 token::burn(cpi_ctx, amount)?;
 Ok(())
}
```

This ensures that the pool is no longer usable for trading after migration and prevents funds from
becoming inaccessible.

[M-02] Pool balance manipulation before migration
Severity
Impact: Medium
Likelihood: Medium

Description

In the migrate_cpmm function, the pool migration is restricted by a maximum pool balance limit of 30
million pc tokens, as shown in the following snippet:
let pool_pc_balance = ctx.accounts.pool_token_pc.amount;
assert!(pool_pc_balance < MAX_POOL_PC_BALANCE, "Migration can only happen
when only 30mm tokens are left in the pool.");

A malicious user can exploit this by observing the upcoming migration transaction and swapping pc
tokens for coin to artificially increase the balance of pool_token_pc . By doing so, they can cause the
pool_pc_balance to exceed the 30 million token limit, resulting in the migration transaction failing.
This can disrupt the migration process and delay or prevent the protocol from completing the migration.
Successful exploitation of this vulnerability can block the migration of the bonding curve to the Raydium
AMM. This could lead to prolonged downtime, affecting liquidity and user trust. If such attacks are
performed repeatedly, it could also create a denial-of-service (DoS) scenario for the migration process.

Recommendations

Pause trading When the migration goal is reached:
When the migration process is triggered and the balance is about to reach the target limit (30 million
pc tokens or less), all trading on the pool should be paused immediately. This will prevent further
swaps from artificially inflating the pool balance during the migration process.

[M-03] Migration to Raydium fails for pools with tokens having
freeze authority enabled
Severity
Impact: Medium
Likelihood: Medium

Description

The Dub allows for the creation of pools with tokens that may have freeze authority enabled. However,
the migration process to Raydium requires that all tokens in the pool have their freeze authority
disabled. This mismatch creates a critical issue where migration attempts for pools containing tokens
with enabled freeze authority will fail.

```rust
raydium_cp_swap::cpi::initialize(
 cpi_ctx,
 token_0_amount,
 token_1_amount,
 0,
 )?;
 }
```
bonding-curve/src/instructions/migrate_cpmm.rs:L145

As a result, migrators attempting to migrate their liquidity from pools containing tokens with enabled
freeze authority will experience failed transactions which leads to user funds becoming stuck in Dub
pool.

The issue affects all pools created in Dub protocol that contain tokens with enabled freeze authority,
potentially impacting a significant portion of pools and users.

References:

https://docs.raydium.io/raydium/pool-creation/creating-a-constant-product-pool

Recommendations

Add a check to ensure the tokens doesn't have an active freeze authority. If you still want to support a
few tokens that have active freeze authority, consider migrating these pools to an alternative DEX.

[M-04] Freeze authority on base mint in deploy_bonding_mint

Severity
Impact: Medium
Likelihood: Medium

Description For SPL tokens, pool creation requires freeze authority disabled
In the deploy_bonding_mint function, the base_mint of the pool is set, and the mint is initialized.
However, there is no check to verify whether the freeze_authority of the base_mint token is set. If
the freeze_authority is assigned to a public key, the account holding this authority can freeze critical
token accounts, such as the fee_vault , which is used during swaps to collect fees. This would result
in a permanent denial of service (DOS) on the swapping functionality for all AMMs relying on this
bonding curve.

Here is the relevant portion of the deploy_bonding_mint function:
```rust
#[account(
 init,
 payer = payer,
 seeds = [
 amm.key().as_ref(),
 mint_bump.key().as_ref()
 ],
 bump,
 mint::decimals = 6,
 mint::authority = amm_authority
)]
pub mint: Box<Account<'info, Mint>>,
// #[account]
/// CHECK:
pub mint_base: AccountInfo<'info>,
```

During the swap process, a fee is calculated and sent to the fee_vault . If the fee_vault is frozen
due to an unchecked freeze_authority , it would prevent swaps, as shown below in the

swap_exact_tokens_for_tokens function:
```rust
let tax = input_pretax * amm.fee as u64 / 10000;
token::transfer(
 CpiContext::new(
 ctx.accounts.token_program.to_account_info(),
 Transfer {
 from: ctx.accounts.trader_account_a.to_account_info(),
 to: ctx.accounts.fee_vault_token_account.to_account_info(),
 authority: ctx.accounts.trader.to_account_info(),
 },
 ),
 tax,
)?;
```

This freeze could render the entire AMM system unusable, as no trades could be processed due to the
inability to transfer fees.
If the freeze_authority of the base_mint is exploited or utilized, it could cause a permanent DOS
on the swapping functionality, making the bonding curve and its AMM useless. Without safeguards, any
malicious or compromised actor with the freeze_authority could disrupt the AMM operations.
Also migrators will not be able to migrate their liquidity from pools due to the migration goal did not get
reached , which leads to user funds becoming stuck in Dub pool.

Recommendation

1. Check for freeze_authority : Ensure that the base_mint does not have a freeze_authority
set, or that it is handled carefully. An example of the check could be:
if mint_account.freeze_authority.is_some() {
 return Err(Error::MintHasFreezeAuthority);
}
2. Display Warnings for Tokens with freeze_authority : If supporting tokens with a
freeze_authority is necessary, display a warning to users in the UI, informing them of the risks
associated with trading or interacting with these tokens.
3. Implement Allowlist for Trusted Tokens: For regulated stablecoins like USDC, which have a
freeze_authority for security reasons, implement an allowlist for trusted tokens while applying
strict checks on other tokens. This ensures the protocol can support widely-used tokens while
minimizing risk.

By applying these changes, the protocol will mitigate the risk of an unexpected DOS due to the freezing
of critical token accounts.

[M-05] Premature token releases in Lock program
Severity
Impact: Medium
Likelihood: Medium

Description

The handle_release function in release.rs lacks proper time-based checks and validation of
unlock criteria before setting claim_approved to true . This could allow premature token releases,
potentially enabling attacks using flash loans to unlock and dump tokens before their intended vesting
date.

// Check if the unlock criteria have been met
 match lockbox.unlock_criteria {
 UnlockCriteria::None => {
 // No specific criteria, always allow release
 },
 UnlockCriteria::BondingPrice { .. } => {
 // let current_time = Clock::get()?.unix_timestamp;
 // require!(current_time >= unlock_time,
ErrorCode::UnlockConditionsNotMet);
 // TODO
 },
 UnlockCriteria::RaydiumPrice { .. } => {
 // Price-based criteria should be checked elsewhere, possibly
off-chain
 // Here we assume it's already verified if this criteria is set
 },
 }
 // Set claim_approved to true
 lockbox.claim_approved = true;
lock/src/instructions/release.rs:L42

Recommendations

Update handle_release to include Time-based checks ensuring current timestamp ≥ scheduled
unlock time. Or Implement a proper validation of specified unlock criteria (e.g., bonding price
thresholds).

[M-06] State inconsistency due to Solana rollback

Severity
Impact: Medium
Likelihood: Medium

Description

Two critical functions in the protocol are vulnerable to state inconsistencies in the event of a Solana
rollback:
Merkle Root Updates: The handle_update_root function in
merkle_distributor/update_root.rs updates the Merkle root, max claim amounts, and resets
claim counters. A rollback after this update could create a mismatch between off-chain data and onchain state, potentially allowing unintended claims, exceeding claim limits, or enabling doubleclaiming.
AMM Pause Mechanism: the update_pause function in bonding_curve/update.rs controls the
AMM's ability to halt trading in emergency situations. However, in the event of a Solana rollback,
this critical security feature could be compromised. If the AMM was paused due to a detected
security threat, a rollback could revert it to an active state, potentially exposing the protocol to the
very threat it was trying to mitigate.

Recommendations

Utilize the LastRestartSlot sysvar to detect outdated configuration states. If the config is outdated,
the protocol should automatically pause until an action is taken by the admin.

Example as an inspiration:

Add a last_updated_slot field to the AMM state struct:

```rust
pub struct AmmState {
 // ... other fields ...
 pub last_updated_slot: u64,
 pub trading_paused: bool,
 // ... other fields ...
}
```

Add a function to check if the config is outdated:

```rust
fn is_config_outdated(amm_state: &AmmState) -> Result<bool> {
 let last_restart_slot = LastRestartSlot::get()?;
 Ok(amm_state.last_updated_slot <=
last_restart_slot.last_restart_slot)
}
```

Modify the swap_exact_tokens_for_tokens and other critical functions to check for outdated
config

```rust
pub fn swap_exact_tokens_for_tokens(ctx:
Context<SwapExactTokensForTokens>, ...) -> Result<()> {
 let amm = &ctx.accounts.amm;
 if is_config_outdated(amm)? || amm.trading_paused {
 return err!(BondingCurveError::TradingPaused);
 }
 // ... rest of the function
}
```
Update the last_updated_slot in the update_pause function

```rust
pub fn update_pause(ctx: Context<UpdatePause>, new_pause: bool) ->
Result<()> {
 require!(ctx.accounts.admin.key() == ctx.accounts.amm.admin,
BondingCurveError::Unauthorized);
 let amm = &mut ctx.accounts.amm;
 amm.trading_paused = new_pause;
 amm.last_updated_slot = Clock::get()?.slot;
 Ok(())
}
```

[M-07] DoS for legitimate AMM creators is possible

Severity
Impact: Medium
Likelihood: Medium

Description

create_amm function in bonding curve is vulnerable to front-running attacks.
A scenario of how this could occur:
A legitimate user submits a transaction to create an AMM with a specific ID.
The attacker quickly submits their own transaction to create an AMM with the same ID, but with
higher gas fees.

The attacker's transaction is processed first, creating the AMM with the attacker's parameters.
The legitimate user's transaction fails due to the AMM ID already being in use.
This could lead to:

DoS for legitimate AMM creators
Creation of malicious AMMs that mimic legitimate ones
The current code doesn't have any mechanism to prevent this type of attack:


```rust
#[derive(Accounts)]
#[instruction(id: Pubkey, fee: u16)]
pub struct CreateAmm<'info> {
 #[account(
 init,
 payer = payer,
 space = Amm::LEN,
 seeds = [id.as_ref()],
 bump,
 constraint = fee < 30000 @ BondingCurveError::InvalidFee,
 )]
 pub amm: Box<Account<'info, Amm>>,
 // ... other fields
}
```
bonding-curve/src/instructions/create_amm.rs:L42
The AMM is created using only the provided id .

Recommendations

To mitigate this, I recommend implementing a sequential numbering. This can be achieved by:
Adding a new account to store the latest AMM sequence number.
Modifying the CreateAmm struct and create_amm function to use this sequence number.

Here's a proposed implementation:

```rust
#[derive(Accounts)]
#[instruction(id: Pubkey, fee: u16)]
pub struct CreateAmm<'info> {
 #[account(
 init,
 payer = payer,
 space = Amm::LEN,
 seeds = [id.as_ref(),
amm_sequence.current_sequence.to_le_bytes().as_ref()],
 bump,
 constraint = fee < 30000 @ BondingCurveError::InvalidFee,
 )]
 pub amm: Box<Account<'info, Amm>>,
 #[account(mut)]
 pub amm_sequence: Account<'info, AmmSequence>,
 // ... other fields
}
#[account]
pub struct AmmSequence {
 pub current_sequence: u64,
}
```


```rust
pub fn create_amm(ctx: Context<CreateAmm>, /* ... other params */) ->
Result<()> {
 // ... existing code
 // Increment and use the sequence number
 ctx.accounts.amm_sequence.current_sequence += 1;
 ctx.accounts.amm.sequence = ctx.accounts.amm_sequence.current_sequence;
 // ... rest of the function
}
```

Please make sure that the AmmSequence account can only be modified by the program itself.

[M-08] Fee rounding enables zero-fee swaps
Severity
Impact: Medium
Likelihood: Medium

Description

In the current swap fee calculation, fees are rounded down, which can result in zero fees being applied
when swapping small amounts of low decimal tokens. This is particularly problematic for tokens with a
low decimal precision (e.g., 3 decimals). For example, if the fee is set at 1% (or 100 basis points) and
the amount to swap is 99 , no fee is applied, effectively allowing a user to swap tokens for free. In the
case of low decimal tokens, a user could repeatedly swap small amounts without incurring any fees.
As shown in the following snippet, the fee is calculated by dividing input_pretax * amm.fee by
10000 :

let tax = input_pretax * amm.fee as u64 / 10000;
The issue arises because the division rounds down, which results in 0 for small input amounts.
This test case demonstrates how the current fee calculation can round down to zero:

#[test]
fn test_fee_rounding_down(){
 let fee = 100; // 1.00% fee
 let input_pretax = 99;
 let tax = input_pretax * fee as u64 / 10000;
 let input_amount_post_fee = input_pretax - tax;
 println!("fee amount: {:?}", tax);
 println!("input amount post fee: {:?}", input_amount_post_fee);
 // logs:
 // fee amount : 0
 // input amount post fee 99
}
In this example, the fee amount is calculated as 0 , meaning the swap proceeds without any fee. This
issue could be exploited by swapping 99 units of a low decimal token repeatedly to avoid paying fees.
This issue allows users to swap certain token amounts without incurring fees, particularly for low
decimal tokens. This can be exploited, leading to potential revenue loss for the protocol and
undermining the fee structure of the bonding curve.
Recommendation
To prevent the fee from rounding down to zero, use a ceiling division ( ceil_div ) instead of a standard
division ( / ), ensuring that the fee is always rounded up
or this can be used :
let tax = input_pretax * amm.fee as u64
 .checked_add(9999) // Add this to round up when dividing
 .ok_or(BondingCurveError::Overflow)?
 / 10000;
This change will ensure that even for small amounts of tokens, a non-zero fee will be taken, preventing
users from bypassing the fee system.

# AUDIT F

8.1. High Findings

[H-01] Front-running on the migration
process
Severity
Impact: High
Likelihood: Medium

Description

```rust
An attacker can front-run the migration transaction by sending a small amount
of token to the pool_authority_mint_account , which can cause the account
closure to fail and disrupt the entire migration process.
Relevant code:
fund_pool_authority_mint_account_from_associated_bonding_curve(&ctx)?;

 let sol_amount = ctx.accounts.bonding_curve.real_sol_reserves - pool_migratio
 fund_pool_authority_wsol_account_from_bonding_curve(&ctx, sol_amount)?;
 create_pool(&ctx, sol_amount)?;
 close_token_account(
 &ctx,
 ctx.accounts.pool_authority_mint_account.to_account_info(),
 )?;
```
The attack scenario is as follows:

1. An attacker submits their own transaction to send a dust amount to a precreated pool_authority_mint_account .
2. If the attacker's transaction is processed before the migration transaction,
pool_authority_mint_account will have a non-zero balance.
7
3. When the migration transaction executes, the operation will fail because the
account has a non-zero balance.

Recommendations

Implement Balance Check and Sweep: At the beginning of the migration
process, check the balance of pool_authority_mint_account and sweep any
unexpected funds to a designated address. For example:
let unexpected_balance = ctx.accounts.pool_authority_mint_account.amount;

```rust
if unexpected_balance > 0 {
 // Transfer unexpected balance to a designated address
 sweep_token(ctx, unexpected_balance, designated_address)?;
}
```
// Proceed with migration process
8
8.2. Medium Findings

[M-01] Insufficient Token Handling in
buy()

Severity

Impact: Medium
Likelihood: Medium


Description


In the buy function, the user specifies an amount of tokens to buy from the
bonding curve by paying SOL. However, if the requested amount exceeds the
available real_token_reserves , the function reverts with an underflow error.
This issue occurs when the function attempts to subtract an amount greater
than the available tokens from the real_token_reserves . As a result, valid
swaps that could partially fulfill the user's request are prevented, and the
bonding curve is not marked as completed.

For example, in the buy function:
9

```rust
pub fn buy(ctx: Context<Buy>, amount: u64, max_sol_cost: u64) -> Result<()> {
 // calculate the sol cost and fee
 let sol_cost = ctx.accounts.bonding_curve.buy_quote(amount as u128);
 let fee = ctx.accounts.global.get_fee(sol_cost);
 // check that the sol cost is within the slippage tolerance
 require!(
 sol_cost + fee <= max_sol_cost,
 PumpError::TooMuchSolRequired
 );
 require_keys_eq!(
 ctx.accounts.associated_bonding_curve.mint,
 ctx.accounts.mint.key(),
 PumpError::MintDoesNotMatchBondingCurve
 );
 require!(
 !ctx.accounts.bonding_curve.complete,
 PumpError::BondingCurveComplete
 );
 // update the bonding curve parameters
 ctx.accounts.bonding_curve.virtual_token_reserves -= amount;
 --> ctx.accounts.bonding_curve.real_token_reserves -= amount; // Reverts if
 // `amount` is greater than reserves
 ctx.accounts.bonding_curve.virtual_sol_reserves += sol_cost;
```

If the amount exceeds the available tokens in real_token_reserves , the
function will fail, halting the execution of the swap instead of selling the
remaining tokens to the user and marking the bonding curve as complete.

Impact

This issue prevents partial purchases when the requested token amount
exceeds the remaining tokens in the real_token_reserves . Users may be
unable to buy tokens even though a portion of their request could be fulfilled.
Additionally, the bonding curve will remain incomplete, causing potential
disruption to the functionality of the protocol and frustrating user experience.

Recommendation

Modify the buy function to handle the case where the requested amount
exceeds the available tokens in the real_token_reserves . If the requested
amount is greater, the function should sell the remaining tokens in the reserve
to the user, update the bonding curve, and mark it as complete. This will
prevent the underflow error and allow valid transactions to be processed.
Suggested Fix:

10

```rust
pub fn buy(ctx: Context<Buy>, amount: u64, max_sol_cost: u64) -> Result<()> {
+
+ // Check if the requested amount exceeds the remaining tokens in the real reserv
+ if amount > ctx.accounts.bonding_curve.real_token_reserves {
+
+ amount = ctx.accounts.bonding_curve.real_token_reserves; // Adjust to sell
+
+ ctx.accounts.bonding_curve.complete = true; // Mark the bonding curve as co
+ }
 // Proceed with the regular buy logic
 let sol_cost = ctx.accounts.bonding_curve.buy_quote(amount as u128);
 let fee = ctx.accounts.global.get_fee(sol_cost);
 // Check slippage tolerance and other conditions...
}
```







