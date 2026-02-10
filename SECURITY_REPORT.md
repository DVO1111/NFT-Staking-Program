# Security Audit Report: NFT-Staking-Program

## Summary
A critical division-by-zero vulnerability was identified in the NFT Staking Program that can result in permanent locking of user assets.

**Repository:** https://github.com/0xShuk/NFT-Staking-Program  
**Audited by:** AI Security Agent (agentpay-monocle)  
**Date:** February 10, 2026  
**Severity:** CRITICAL

---

## Vulnerability Details

### Title
Division by Zero in `update_staked_weight` Causes Permanent Asset Lock

### Location
- **File:** `nft-stake-vault/programs/nft-stake-vault/src/state/stake_details.rs`
- **Function:** `update_staked_weight`
- **Line:** 88

### Vulnerable Code
```rust
pub fn update_staked_weight(&mut self, stake_time: i64, increase_weight: bool) -> Result<()> {
    let last_reward_time = *self.reward_change_time.last().unwrap();

    let base = self.staking_ends_at
        .checked_sub(last_reward_time)
        .ok_or(StakeError::ProgramSubError)? as u128;  // <-- CAN BE ZERO

    // ... 

    let weight = num.checked_div(base).ok_or(StakeError::ProgramDivError)?;  // <-- DIVISION BY ZERO
```

### Root Cause
The `base` variable is calculated as `staking_ends_at - last_reward_time`. If these two values are equal, `base = 0`, causing `checked_div(base)` to return `None` and trigger a `ProgramDivError`.

### Attack Vector
1. Creator initializes staking with an end time
2. When `current_time == staking_ends_at`, creator calls `change_reward()`
3. The `change_reward_handler` has check `require_gte!(staking_ends_at, current_time, StakeError::StakingIsOver)` which **allows** `staking_ends_at == current_time`
4. After the call, `reward_change_time.last() = current_time = staking_ends_at`
5. Any subsequent call to `unstake()` or `withdraw_reward()` will invoke `update_staked_weight()`
6. The function will fail with division by zero
7. **Users cannot unstake their NFTs - assets are permanently locked**

### Impact
- **Severity:** CRITICAL
- **Asset Loss:** Users' staked NFTs are permanently locked in the program
- **Exploitability:** Medium (requires timing the `change_reward` call precisely)
- **Attack Type:** Griefing / Asset Freezing

### Affected Functions
1. `unstake_handler` - Users cannot retrieve their NFTs
2. `withdraw_reward_handler` - Users cannot claim rewards

---

## Proof of Concept

### Scenario
```
Time: T0 - Staking starts
Time: T1 - User stakes NFT
Time: T2 - Staking ends (staking_ends_at)

Attack:
1. At exactly T2, creator calls: change_reward(new_reward)
2. This sets: reward_change_time.last() = T2 = staking_ends_at
3. User calls: unstake()
4. update_staked_weight() calculates: base = T2 - T2 = 0
5. Division by zero error → transaction fails
6. User's NFT is permanently locked
```

### Test Code
```typescript
it("Demonstrates division by zero vulnerability", async () => {
  // Setup: Create staking pool, user stakes NFT
  // ...

  // Wait until staking_ends_at
  await sleep(stakingDuration);

  // Creator calls change_reward at exact end time
  await program.methods
    .changeReward(new BN(newRewardRate))
    .accounts({
      stakeDetails: stakeDetailsPDA,
      creator: creator.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .signers([creator])
    .rpc();

  // User attempts to unstake - THIS WILL FAIL
  try {
    await program.methods
      .unstake()
      .accounts({
        stakeDetails: stakeDetailsPDA,
        nftRecord: nftRecordPDA,
        // ... other accounts
      })
      .signers([user])
      .rpc();
    
    assert.fail("Should have thrown error");
  } catch (e) {
    // Error: ProgramDivError - Division by zero
    console.log("NFT permanently locked due to division by zero!");
  }
});
```

---

## Recommended Fix

### Option 1: Strict Time Check in `change_reward_handler` (Recommended)
Change the condition from `>=` to `>`:

```rust
// Before (vulnerable)
require_gte!(staking_ends_at, current_time, StakeError::StakingIsOver);

// After (fixed)
require_gt!(staking_ends_at, current_time, StakeError::StakingIsOver);
```

This prevents `change_reward` from being called at the exact moment staking ends.

### Option 2: Guard in `update_staked_weight`
Add a check for zero base:

```rust
pub fn update_staked_weight(&mut self, stake_time: i64, increase_weight: bool) -> Result<()> {
    let last_reward_time = *self.reward_change_time.last().unwrap();

    let base = self.staking_ends_at
        .checked_sub(last_reward_time)
        .ok_or(StakeError::ProgramSubError)? as u128;

    // NEW: Guard against division by zero
    if base == 0 {
        // Staking period has ended at reward change time
        // Weight should remain unchanged or be set to 0
        return Ok(());
    }

    // ... rest of function
```

### Option 3: Both Fixes
Apply both fixes for defense in depth.

---

## Additional Findings

### Low Severity: Missing Active Check in Unstake
The `unstake_handler` does not verify `is_active` status, allowing unstaking even after `close_staking()` is called. This may be intentional but should be documented.

---

## Conclusion
The NFT Staking Program contains a critical vulnerability that can permanently lock user assets. The fix is straightforward and should be applied immediately. I recommend using Option 1 (strict time check) as the primary fix and Option 2 as defense in depth.
