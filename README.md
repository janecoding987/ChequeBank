# ChequeBank

A smart contract system for managing e-cheques with EIP-712 structured signatures, supporting cheque creation, activation, redemption, revocation, and sign-over functionality.

## Features

- ✅ **EIP-712 Structured Signatures**: Uses EIP-712 standard for secure off-chain signatures, preventing replay attacks
- ✅ **Cheque Sign-Over**: Supports up to 6 sign-overs, enabling cheque transfer
- ✅ **Batch Operations**: Atomic batch operations via `multicall`
- ✅ **Storage Optimization**: Uses struct packing optimization, each cheque state occupies only 3 storage slots
- ✅ **Reentrancy Protection**: Uses OpenZeppelin's `ReentrancyGuard` to protect critical functions
- ✅ **Safe Transfers**: Uses `call` for ETH transfers, avoiding fixed gas limit issues

## ⚠️ Important Notes

### Relationship Between Cheque Activation and Redemption

**Important**: An activated (`Active`) cheque **may** fail during redemption (`redeem`).

**Reasons**:
1. **Off-chain Generation**: Cheque creation and signing process is completely off-chain, and does not require the payer to lock any ETH in the contract in advance
2. **No Fund Locking**: The `active` function only verifies the validity of the cheque signature, and **does not require** the payer to deposit funds in advance
3. **Balance Check at Redemption**: The contract only checks if the payer's account balance is sufficient when the payee attempts to `redeem`

**This means**:
- ✅ The payer can deposit funds at any time after cheque activation and before redemption
- ⚠️ If the payer's balance is insufficient at redemption time, `redeem` will fail and revert



## Contract Architecture

### Data Structures

#### ChequeInfo
```solidity
struct ChequeInfo {
    uint256 amount;      // Cheque amount
    uint32 validFrom;    // Valid from timestamp
    uint32 validThru;    // Valid until timestamp
    uint32 nonce;        // Random number to prevent chequeId collision
    address payee;       // Payee address
    address payer;       // Payer address
}
```

#### ChequeState
```solidity
struct ChequeState {
    uint256 amount;          // Cheque amount
    uint32 validFrom;        // Valid from timestamp
    uint32 validThru;        // Valid until timestamp
    uint32 nonce;            // Random number
    address payee;           // Current payee (updated on each sign-over)
    address payer;           // Payer
    ChequeStatus status;     // Cheque status
    uint8 signOverCount;     // Number of sign-overs (max 6)
}
```

#### ChequeStatus Enum
- `None` (0): Cheque does not exist
- `Active` (1): Cheque is activated and can be redeemed
- `Revoked` (2): Cheque has been revoked
- `Redeemed` (3): Cheque has been redeemed

## Main Functions

### 1. deposit() payable external

**Function**: Deposit ETH into the contract.

**Semantics**:
- Deposits the sent ETH into the caller's account balance
- If `msg.value == 0`, returns immediately without executing any operation
- Emits `Deposited` event

**Gas Consumption**:
- Minimum: 23,670 gas
- Average: 45,546 gas
- Maximum: 47,637 gas

**Example**:
```solidity
chequeBank.deposit{value: 1 ether}();
```

---

### 2. withdraw(uint256 amount, address payable recipient) external

**Function**: Withdraw ETH from the contract to a specified address.

**Semantics**:
- Deducts the specified amount from the caller's account balance
- Transfers ETH to the `recipient` address
- Requires the caller to have sufficient balance and `recipient` to be non-zero
- Emits `Withdrawn` event

**Gas Consumption**:
- Minimum: 29,321 gas
- Average: 41,403 gas
- Maximum: 66,582 gas

**Example**:
```solidity
chequeBank.withdraw(1 ether, payable(recipient));
```

---

### 3. active(Cheque calldata chequeData) external

**Function**: Activate a cheque, setting its status to `Active`.

**Semantics**:
- Verifies the cheque's EIP-712 signature
- Checks cheque validity period (`validFrom` and `validThru`)
- Verifies that `payer` and `payee` are not zero addresses
- Computes `chequeId` and checks if already activated
- Stores cheque information on-chain, sets status to `Active`
- Emits `ChequeActivated` event

**⚠️ Important**:
- The `active` function **does not check** the payer's account balance
- The payer **does not need** to deposit funds in advance before activation
- After activation, if the payer's balance is insufficient, `redeem` will fail

**Gas Consumption**:
- Minimum: 37,931 gas
- Average: 98,022 gas
- Maximum: 113,092 gas

**Example**:
```solidity
IChequeBank.Cheque memory cheque = IChequeBank.Cheque({
    chequeInfo: chequeInfo,
    sig: signature
});
chequeBank.active(cheque);
```

---

### 4. redeem(bytes32 chequeId) external

**Function**: Redeem an activated cheque.

**Semantics**:
- Reads cheque state from storage
- Verifies cheque status is `Active`
- Checks cheque validity period
- Verifies caller is the current payee
- **Verifies payer has sufficient balance** (reverts with `InsufficientBalance` error if insufficient)
- Transfers funds from payer's account to payee's account
- Updates cheque status to `Redeemed` and clears other fields to save gas
- Emits `ChequeRedeemed` event

**⚠️ Important**:
- `redeem` checks the payer's account balance
- If the payer's balance is insufficient, the transaction will **revert and fail**
- Even if the cheque status is `Active`, `redeem` will still fail if the payer has not deposited sufficient funds

**Gas Consumption**:
- Minimum: 6,801 gas
- Average: 41,475 gas
- Maximum: 60,560 gas

**Example**:
```solidity
bytes32 chequeId = _computeChequeId(chequeInfo);
// Recommended: check cheque validity first
bool isValid = chequeBank.isChequeValid(payee, cheque, signOverData);
require(isValid, "Cheque is not valid or payer balance insufficient");
// Then redeem
chequeBank.redeem(chequeId);
```

---

### 5. revoke(bytes32 chequeId) external

**Function**: Revoke an activated cheque.

**Semantics**:
- Reads cheque state from storage
- Verifies cheque status is `Active`
- Determines revocation authority:
  - If `signOverCount == 0`: only `payer` can revoke
  - If `signOverCount > 0`: only current `payee` can revoke
- Updates cheque status to `Revoked` and clears other fields to save gas
- Emits `ChequeRevoked` event

**Gas Consumption**:
- Minimum: 8,318 gas
- Average: 30,860 gas
- Maximum: 37,116 gas

**Example**:
```solidity
bytes32 chequeId = _computeChequeId(chequeInfo);
chequeBank.revoke(chequeId);
```

---

### 6. notifySignOver(SignOver calldata signOverData) external

**Function**: Notify the contract of a cheque sign-over.

**Semantics**:
- Verifies the sign-over's EIP-712 signature
- Verifies cheque status is `Active`
- Verifies `oldPayee` matches current `payee`
- Verifies `newPayee` is not zero address
- Verifies `counter` is correct (should be `signOverCount + 1`)
- Verifies sign-over count has not exceeded maximum (6)
- Updates current `payee` to `newPayee` and increments `signOverCount`
- Emits `SignOverNotified` event

**Gas Consumption**:
- Minimum: 18,266 gas
- Average: 45,084 gas
- Maximum: 51,102 gas

**Example**:
```solidity
IChequeBank.SignOver memory signOver = IChequeBank.SignOver({
    signOverInfo: signOverInfo,
    sig: signature
});
chequeBank.notifySignOver(signOver);
```

---

### 7. multicall(bytes[] calldata data) external returns (bytes[] memory results)

**Function**: Batch execute multiple function calls with atomicity guarantee.

**Semantics**:
- Executes each function call in the `data` array sequentially
- If any call fails, the entire operation reverts (atomicity guarantee)
- Returns an array of results from all calls
- Note: `multicall` itself does not use the `nonReentrant` modifier, but the called functions do

**Gas Consumption**:
- Minimum: 116,248 gas
- Average: 127,734 gas
- Maximum: 146,044 gas

**Example**:
```solidity
bytes[] memory calls = new bytes[](2);
calls[0] = abi.encodeWithSelector(ChequeBank.active.selector, cheque);
calls[1] = abi.encodeWithSelector(ChequeBank.redeem.selector, chequeId);
bytes[] memory results = chequeBank.multicall(calls);
```

---

### 8. getBalance(address account) external view returns (uint256)

**Function**: Query the account balance of a specified address.

**Semantics**:
- Returns the ETH balance of `account` in the contract
- This is a view function and does not consume gas (when querying)

**Gas Consumption** (when called):
- Fixed: 2,917 gas

**Example**:
```solidity
uint256 balance = chequeBank.getBalance(account);
```

---

### 9. getCheque(bytes32 chequeId) external view returns (ChequeState memory)

**Function**: Query the state information of a specified cheque.

**Semantics**:
- Returns the complete cheque state corresponding to `chequeId`
- This is a view function and does not consume gas (when querying)

**Gas Consumption** (when called):
- Fixed: 9,608 gas

**Example**:
```solidity
IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
```

---

### 10. isChequeValid(address payee, Cheque calldata chequeData, SignOver[] calldata signOverData) external view returns (bool)

**Function**: Verify if a cheque is valid and payable to the specified payee.

**Semantics**:
- Verifies the cheque's EIP-712 signature
- Checks cheque validity period
- Checks if payer has sufficient balance
- Checks cheque status (returns `false` if revoked or redeemed)
- If `signOverData` is provided, verifies the complete sign-over chain
- Verifies if the final payee is `payee`
- Returns `true` if the cheque is valid, otherwise returns `false`

**Gas Consumption**:
- Minimum: 9,795 gas
- Average: 22,713 gas
- Maximum: 35,645 gas

**Example**:
```solidity
IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](0);
bool isValid = chequeBank.isChequeValid(payee, cheque, signOverData);
```

---

## Gas Consumption Summary

| Function | Min Gas | Avg Gas | Max Gas | Description |
|----------|---------|---------|---------|-------------|
| `deposit` | 23,670 | 45,546 | 47,637 | Basic deposit operation |
| `withdraw` | 29,321 | 41,403 | 66,582 | Includes ETH transfer |
| `active` | 37,931 | 98,022 | 113,092 | Includes signature verification and storage |
| `redeem` | 6,801 | 41,475 | 60,560 | Includes balance transfer |
| `revoke` | 8,318 | 30,860 | 37,116 | Status update |
| `notifySignOver` | 18,266 | 45,084 | 51,102 | Includes signature verification |
| `multicall` | 116,248 | 127,734 | 146,044 | Batch operations |
| `getBalance` | 2,917 | 2,917 | 2,917 | View function |
| `getCheque` | 9,608 | 9,608 | 9,608 | View function |
| `isChequeValid` | 9,795 | 22,713 | 35,645 | View function with validation logic |

**Note**: Gas consumption varies depending on the actual execution path, especially:
- `active` has higher gas consumption due to EIP-712 signature verification and storage operations
- `multicall` gas consumption depends on the number of function calls included
- View functions do not consume gas when querying, but do consume gas when called internally by contracts

---

## Test Coverage

### Overall Coverage

```
╭--------------------------+------------------+------------------+----------------+-----------------╮
| File                     | % Lines          | % Statements     | % Branches     | % Funcs         |
+===================================================================================================+
| contracts/ChequeBank.sol | 98.30% (173/176) | 98.39% (183/186) | 92.11% (35/38) | 100.00% (22/22) |
|--------------------------+------------------+------------------+----------------+-----------------|
| Total                    | 98.30% (173/176) | 98.39% (183/186) | 92.11% (35/38) | 100.00% (22/22) |
╰--------------------------+------------------+------------------+----------------+-----------------╯
```

### Coverage Details

- **Function Coverage**: 100.00% (22/22) ✅
  - All public and internal functions have test coverage

- **Statement Coverage**: 98.39% (183/186) ✅
  - Almost all code statements have test coverage

- **Line Coverage**: 98.30% (173/176) ✅
  - Almost all code lines have test coverage

- **Branch Coverage**: 92.11% (35/38) ✅
  - Over 90% of branches have test coverage
  - Covers major error handling paths and edge conditions
  - Includes various failure scenarios for sign-over chain validation, multicall error handling, etc.

### Test Suite

- **Total Tests**: 77
- **Passed**: 77 ✅
- **Failed**: 0

**Test Categories**:
- Functional tests: 44
- Exception tests: 13
- Gas tests: 10
- Branch coverage tests: 10 (newly added)
  - Various edge cases and error paths for `isChequeValid`
  - Various failure scenarios for sign-over chain validation
  - Multicall error handling

**Test Coverage**:
- ✅ Normal flow of all public functions
- ✅ Error handling for all error cases
- ✅ Edge conditions (zero values, maximum values, etc.)
- ✅ Reentrancy protection
- ✅ Rejection of direct ETH transfers
- ✅ Arithmetic overflow protection
- ✅ Multicall atomicity

---

## Security Features

1. **EIP-712 Structured Signatures**: Prevents signature replay attacks and cross-chain replay
2. **Reentrancy Protection**: Uses OpenZeppelin's `ReentrancyGuard` to protect critical functions
3. **Safe Transfers**: Uses `call` for ETH transfers, avoiding fixed gas limit issues
4. **Overflow Protection**: Solidity 0.8+ automatically checks for arithmetic overflow
5. **Signature Verification**: Uses OpenZeppelin's `ECDSA.recover` for secure signature recovery
6. **State Management**: Clear cheque state transitions, preventing state confusion

---

## Usage Examples

### Complete Flow: Create, Activate, Sign-Over, Redeem

```solidity
// 1. Payer deposits
chequeBank.deposit{value: 10 ether}();

// 2. Create cheque (off-chain)
IChequeBank.ChequeInfo memory chequeInfo = IChequeBank.ChequeInfo({
    amount: 10 ether,
    validFrom: block.timestamp,
    validThru: block.timestamp + 30 days,
    nonce: 1,
    payee: payeeAddress,
    payer: payerAddress
});
// Sign using EIP-712
bytes memory signature = signCheque(chequeInfo, payerPrivateKey);

// 3. Activate cheque (on-chain)
IChequeBank.Cheque memory cheque = IChequeBank.Cheque({
    chequeInfo: chequeInfo,
    sig: signature
});
chequeBank.active(cheque);

// 4. Sign over cheque (optional)
IChequeBank.SignOverInfo memory signOverInfo = IChequeBank.SignOverInfo({
    counter: 1,
    oldPayee: payeeAddress,
    newPayee: newPayeeAddress,
    chequeId: _computeChequeId(chequeInfo)
});
bytes memory signOverSig = signSignOver(signOverInfo, payeePrivateKey);
IChequeBank.SignOver memory signOver = IChequeBank.SignOver({
    signOverInfo: signOverInfo,
    sig: signOverSig
});
chequeBank.notifySignOver(signOver);

// 5. Redeem cheque
bytes32 chequeId = _computeChequeId(chequeInfo);
chequeBank.redeem(chequeId);
```

### Using Multicall for Batch Operations

```solidity
bytes[] memory calls = new bytes[](3);
calls[0] = abi.encodeWithSelector(ChequeBank.active.selector, cheque);
calls[1] = abi.encodeWithSelector(ChequeBank.notifySignOver.selector, signOver);
calls[2] = abi.encodeWithSelector(ChequeBank.redeem.selector, chequeId);

chequeBank.multicall(calls);
```

---

## Development

### Install Dependencies

```bash
npm install
forge install foundry-rs/forge-std
```

### Build

```bash
forge build
```

### Run Tests

```bash
# Run all tests
forge test

# Run tests with gas report
forge test --gas-report

# Run tests with verbose output
forge test -vvv
```

### Code Coverage

```bash
# Generate coverage report
forge coverage

# Generate LCOV format coverage report
forge coverage --report lcov
```

---

## License

MIT License
