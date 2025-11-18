// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IChequeBank} from "./interfaces/IChequeBank.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title ChequeBank
 * @notice A smart contract for managing e-cheques with EIP-712 structured signatures
 * @dev Implements deposit, withdrawal, cheque issuance, redemption, revocation, and sign-over functionality
 */
contract ChequeBank is IChequeBank, ReentrancyGuard {
    // ============ EIP-712 Constants ============
    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
    );
    
    bytes32 public constant CHEQUE_INFO_TYPEHASH = keccak256(
        "ChequeInfo(uint256 amount,uint32 validFrom,uint32 validThru,uint32 nonce,address payee,address payer)"
    );
    
    bytes32 public constant SIGN_OVER_INFO_TYPEHASH = keccak256(
        "SignOverInfo(uint8 counter,address oldPayee,address newPayee,bytes32 chequeId)"
    );
    
    string private constant DOMAIN_NAME = "ChequeBank";
    string private constant DOMAIN_VERSION = "1";
    
    bytes32 public immutable DOMAIN_SEPARATOR;
    
    // ============ State Variables ============
    mapping(address => uint256) private balances;
    mapping(bytes32 => ChequeState) private cheques;  // Flattened storage for cheque info and state
    
    // ============ Events ============
    event Deposited(address indexed depositor, uint256 amount);
    event Withdrawn(address indexed withdrawer, uint256 amount, address indexed recipient);
    event ChequeActivated(
        bytes32 indexed chequeId,
        address indexed payer,
        address indexed payee,
        uint256 amount,
        uint32 nonce,
        uint32 validFrom,
        uint32 validThru
    );
    event ChequeRedeemed(
        bytes32 indexed chequeId,
        address indexed payer,
        address indexed payee,
        uint256 amount
    );
    event ChequeRevoked(bytes32 indexed chequeId, address indexed revoker);
    event SignOverNotified(
        bytes32 indexed chequeId,
        address indexed oldPayee,
        address indexed newPayee,
        uint8 counter
    );
    
    // ============ Errors ============
    error InsufficientBalance();
    error InvalidSignature();
    error ChequeNotActive();
    error ChequeAlreadyActive();
    error InvalidPayee();
    error InvalidOldPayee();
    error InvalidNewPayee();
    error ChequeExpired();
    error ChequeNotYetValid();
    error MaxSignOversReached();
    error InvalidCounter();
    error Unauthorized();
    error TransferFailed();
    error ZeroAddress();
    
    // ============ Constructor ============
    constructor() {
        DOMAIN_SEPARATOR = _domainSeparator();
    }
    
    // ============ EIP-712 Helper Functions ============
    /**
     * @notice Compute the EIP-712 domain separator
     * @return The domain separator hash
     */
    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256(bytes(DOMAIN_NAME)),
            keccak256(bytes(DOMAIN_VERSION)),
            block.chainid,
            address(this),
            bytes32(0)
        ));
    }
    
    /**
     * @notice Compute chequeId from cheque information
     * @param chequeInfo The cheque information
     * @return The cheque ID (keccak256 hash of amount, validFrom, validThru, nonce, payee, payer)
     */
    function _computeChequeId(ChequeInfo memory chequeInfo) 
        internal pure returns (bytes32) 
    {
        return keccak256(abi.encodePacked(
            chequeInfo.amount,
            chequeInfo.validFrom,
            chequeInfo.validThru,
            chequeInfo.nonce,
            chequeInfo.payee,
            chequeInfo.payer
        ));
    }
    
    /**
     * @notice Hash a ChequeInfo struct according to EIP-712
     * @param chequeInfo The cheque information to hash (includes nonce instead of chequeId)
     * @return The struct hash
     */
    function _hashChequeInfo(ChequeInfo memory chequeInfo) 
        internal pure returns (bytes32) 
    {
        return keccak256(abi.encode(
            CHEQUE_INFO_TYPEHASH,
            chequeInfo.amount,
            chequeInfo.validFrom,
            chequeInfo.validThru,
            chequeInfo.nonce,
            chequeInfo.payee,
            chequeInfo.payer
        ));
    }
    
    /**
     * @notice Hash a SignOverInfo struct according to EIP-712
     * @param signOverInfo The sign-over information to hash
     * @return The struct hash
     */
    function _hashSignOverInfo(SignOverInfo memory signOverInfo) 
        internal pure returns (bytes32) 
    {
        return keccak256(abi.encode(
            SIGN_OVER_INFO_TYPEHASH,
            signOverInfo.counter,
            signOverInfo.oldPayee,
            signOverInfo.newPayee,
            signOverInfo.chequeId
        ));
    }
    
    /**
     * @notice Compute the final EIP-712 message hash for a cheque
     * @param chequeInfo The cheque information (includes nonce for signature)
     * @return The message hash ready for signature verification
     */
    function _hashCheque(ChequeInfo memory chequeInfo) 
        internal view returns (bytes32) 
    {
        bytes32 structHash = _hashChequeInfo(chequeInfo);
        return keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            structHash
        ));
    }
    
    /**
     * @notice Compute the final EIP-712 message hash for a sign-over
     * @param signOverInfo The sign-over information
     * @return The message hash ready for signature verification
     */
    function _hashSignOver(SignOverInfo memory signOverInfo) 
        internal view returns (bytes32) 
    {
        bytes32 structHash = _hashSignOverInfo(signOverInfo);
        return keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            structHash
        ));
    }
    
    /**
     * @notice Verify a cheque signature
     * @param cheque The cheque with signature
     * @return True if signature is valid
     */
    function _verifyChequeSignature(Cheque memory cheque) 
        internal view returns (bool) 
    {
        bytes32 messageHash = _hashCheque(cheque.chequeInfo);
        address signer = ECDSA.recover(messageHash, cheque.sig);
        return signer == cheque.chequeInfo.payer;
    }
    
    /**
     * @notice Verify a sign-over signature
     * @param signOver The sign-over with signature
     * @return True if signature is valid
     */
    function _verifySignOverSignature(SignOver memory signOver) 
        internal view returns (bool) 
    {
        bytes32 messageHash = _hashSignOver(signOver.signOverInfo);
        address signer = ECDSA.recover(messageHash, signOver.sig);
        return signer == signOver.signOverInfo.oldPayee;
    }
    
    // ============ Public View Functions ============
    /**
     * @notice Get the balance of an address
     * @param account The address to query
     * @return The balance of the address
     */
    function getBalance(address account) external view returns (uint256) {
        return balances[account];
    }
    
    /**
     * @notice Get the state of a cheque
     * @param chequeId The cheque ID to query
     * @return The cheque state
     */
    function getCheque(bytes32 chequeId) external view returns (ChequeState memory) {
        return cheques[chequeId];
    }
    
    // ============ Cheque State Helper Functions ============
    // Note: payee always contains the current valid payee (updated on each sign-over)
    // - When signOverCount == 0: it's the original payee
    // - When signOverCount > 0: it's the current payee after sign-overs
    
    /**
     * @notice Verify a sign-over chain segment
     * @param signOverData Array of sign-over data
     * @param chequeId The cheque ID
     * @param startPayee The expected oldPayee for the first sign-over
     * @return isValid True if the chain is valid
     * @return finalPayee The final payee after the sign-over chain (address(0) if invalid)
     */
    function _verifySignOverChainSegment(
        SignOver[] calldata signOverData,
        bytes32 chequeId,
        address startPayee
    ) internal view returns (bool isValid, address finalPayee) {
        address expectedOldPayee = startPayee;
        for (uint256 i = 0; i < signOverData.length; i++) {
            // Verify sign-over signature
            if (!_verifySignOverSignature(signOverData[i])) {
                return (false, address(0));  // Invalid signature
            }
            
            // Verify cheque ID matches
            if (signOverData[i].signOverInfo.chequeId != chequeId) {
                return (false, address(0));  // Invalid cheque ID
            }
            
            // Verify counter (should be i + 1)
            // casting to 'uint8' is safe because i is in range [0, 5] (max 6 sign-overs),
            // so i + 1 is in range [1, 6], which fits in uint8
            // forge-lint: disable-next-line(unsafe-typecast)
            if (signOverData[i].signOverInfo.counter != uint8(i + 1)) {
                return (false, address(0));  // Invalid counter
            }
            
            // Verify chain continuity
            if (signOverData[i].signOverInfo.oldPayee != expectedOldPayee) {
                return (false, address(0));  // Chain discontinuity
            }
            
            expectedOldPayee = signOverData[i].signOverInfo.newPayee;
        }
        
        return (true, expectedOldPayee);
    }
    
    /**
     * @notice Validate cheque timing
     * @param validFrom Start timestamp
     * @param validThru End timestamp
     */
    function _validateChequeTiming(uint32 validFrom, uint32 validThru) internal view {
        if (block.timestamp < validFrom) {
            revert ChequeNotYetValid();
        }
        if (block.timestamp > validThru) {
            revert ChequeExpired();
        }
    }
    
    /**
     * @notice Safely transfer ETH using call
     * @param to The recipient address
     * @param amount The amount to transfer
     */
    function _safeTransferEth(address to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount}("");
        if (!success) {
            revert TransferFailed();
        }
    }
    
    // ============ Public Functions ============
    
    /**
     * @notice Deposit Ether to the bank
     */
    function deposit() external payable override nonReentrant {
        if (msg.value == 0) return;
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }
    
    /**
     * @notice Withdraw Ether from the bank to a specified recipient
     * @param amount The amount to withdraw
     * @param recipient The recipient address
     */
    function withdraw(uint256 amount, address payable recipient) external override nonReentrant {
        if (balances[msg.sender] < amount) {
            revert InsufficientBalance();
        }
        if (recipient == address(0)) {
            revert ZeroAddress();
        }
        balances[msg.sender] -= amount;
        _safeTransferEth(recipient, amount);
        emit Withdrawn(msg.sender, amount, recipient);
    }
    
    /**
     * @notice Activate a cheque (verify signature, store info, set status to Active)
     * @param chequeData The cheque with signature to activate
     */
    function active(Cheque calldata chequeData) external override nonReentrant {
        // Verify signature
        if (!_verifyChequeSignature(chequeData)) {
            revert InvalidSignature();
        }
        
        // Verify timing
        _validateChequeTiming(
            chequeData.chequeInfo.validFrom,
            chequeData.chequeInfo.validThru
        );

        // Validate payer and payee addresses
        if (chequeData.chequeInfo.payer == address(0) || chequeData.chequeInfo.payee == address(0)) {
            revert ZeroAddress();
        }

        // Compute chequeId from cheque information
        bytes32 chequeId = _computeChequeId(chequeData.chequeInfo);
        ChequeState storage cheque = cheques[chequeId];
        // Check if already activated
        if (cheque.status != ChequeStatus.None) {
            revert ChequeAlreadyActive();
        }

        // Store flattened cheque data (without chequeId, as it's the mapping key)
        // payee stores the current payee (original payee when signOverCount == 0)
        cheque.amount = chequeData.chequeInfo.amount;
        cheque.validFrom = chequeData.chequeInfo.validFrom;
        cheque.validThru = chequeData.chequeInfo.validThru;
        cheque.nonce = chequeData.chequeInfo.nonce;
        cheque.payee = chequeData.chequeInfo.payee;
        cheque.payer = chequeData.chequeInfo.payer;
        cheque.status = ChequeStatus.Active;
        cheque.signOverCount = 0;
        
        emit ChequeActivated(
            chequeId,
            chequeData.chequeInfo.payer,
            chequeData.chequeInfo.payee,
            chequeData.chequeInfo.amount,
            chequeData.chequeInfo.nonce,
            chequeData.chequeInfo.validFrom,
            chequeData.chequeInfo.validThru
        );
    }
    
    /**
     * @notice Redeem a cheque (only chequeId needed, reads from storage)
     * @param chequeId The cheque ID to redeem
     */
    function redeem(bytes32 chequeId) external override nonReentrant {
        // Get cheque data from storage
        ChequeState storage cheque = cheques[chequeId];
        // Verify status
        if (cheque.status != ChequeStatus.Active) {
            revert ChequeNotActive();
        }
        
        // Verify timing
        _validateChequeTiming(cheque.validFrom, cheque.validThru);
        
        // Verify balance
        if (balances[cheque.payer] < cheque.amount) {
            revert InsufficientBalance();
        }
        
        // Verify payee (payee always contains the current valid payee)
        if (msg.sender != cheque.payee) {
            revert InvalidPayee();
        }
        
        // Save data for event before clearing
        address payer = cheque.payer;
        uint256 amount = cheque.amount;
        
        // Transfer funds
        balances[payer] -= amount;
        balances[msg.sender] += amount;
        
        // Update state and clear other fields to save gas
        cheque.amount = 0;
        cheque.validFrom = 0;
        cheque.validThru = 0;
        cheque.nonce = 0;
        cheque.payee = address(0);
        cheque.payer = address(0);
        cheque.status = ChequeStatus.Redeemed;
        cheque.signOverCount = 0;
        
        emit ChequeRedeemed(
            chequeId,
            payer,
            msg.sender,
            amount
        );
    }
    
    /**
     * @notice Revoke a cheque (only chequeId needed)
     * @dev If signOverCount == 0: only payer can revoke
     *      If signOverCount > 0: only current payee can revoke
     * @param chequeId The cheque ID to revoke
     */
    function revoke(bytes32 chequeId) external override nonReentrant {
        // Get cheque data from storage
        ChequeState storage cheque = cheques[chequeId];
        // Verify status
        if (cheque.status != ChequeStatus.Active) {
            revert ChequeNotActive();
        }
        
        // Get current revoker: payer if no sign-over, current payee if signed over
        address revoker = cheque.signOverCount == 0 ? cheque.payer : cheque.payee;
        if (msg.sender != revoker) {
            revert Unauthorized();
        }
        
        // Update state and clear other fields to save gas
        cheque.amount = 0;
        cheque.validFrom = 0;
        cheque.validThru = 0;
        cheque.nonce = 0;
        cheque.payee = address(0);
        cheque.payer = address(0);
        cheque.status = ChequeStatus.Revoked;
        cheque.signOverCount = 0;
        
        emit ChequeRevoked(chequeId, msg.sender);
    }
    
    /**
     * @notice Notify the contract of a cheque sign-over (only SignOver needed)
     * @param signOverData The sign-over data with signature
     */
    function notifySignOver(SignOver calldata signOverData) external override nonReentrant {
        // Verify sign-over signature
        if (!_verifySignOverSignature(signOverData)) {
            revert InvalidSignature();
        }
        
        bytes32 chequeId = signOverData.signOverInfo.chequeId;
        ChequeState storage cheque = cheques[chequeId];
        // Verify status is Active
        if (cheque.status != ChequeStatus.Active) {
            revert ChequeNotActive();
        }
        
        // Verify oldPayee matches current payee (payee always contains the current valid payee)
        if (signOverData.signOverInfo.oldPayee != cheque.payee) {
            revert InvalidOldPayee();
        }

        if (signOverData.signOverInfo.newPayee == address(0)) {
            revert InvalidNewPayee();
        }
        
        // Verify counter
        uint8 expectedCounter = cheque.signOverCount + 1;
        if (signOverData.signOverInfo.counter != expectedCounter) {
            revert InvalidCounter();
        }
        
        // Verify max sign-overs
        if (cheque.signOverCount >= 6) {
            revert MaxSignOversReached();
        }
        
        // Update state: update payee to new payee and increment sign-over count
        cheque.payee = signOverData.signOverInfo.newPayee;
        cheque.signOverCount = signOverData.signOverInfo.counter;
        
        emit SignOverNotified(
            chequeId,
            signOverData.signOverInfo.oldPayee,
            signOverData.signOverInfo.newPayee,
            signOverData.signOverInfo.counter
        );
    }
    
    /**
     * @notice Batch operations (atomic: all succeed or all revert)
     * @dev Reentrancy protection is handled by individual functions (redeem, revoke, etc.)
     * @param data Array of encoded function calls
     * @return results Array of return values from each function call
     */
    function multicall(bytes[] calldata data) 
        external 
        override 
        returns (bytes[] memory results) 
    {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(data[i]);
            if (!success) {
                // Revert with the original error message if available
                if (result.length > 0) {
                    assembly {
                        let returndata_size := mload(result)
                        revert(add(32, result), returndata_size)
                    }
                } else {
                    revert("Multicall failed");
                }
            }
            results[i] = result;
        }
    }
    
    /**
     * @notice Check if a cheque is valid and payable to a payee
     * @param payee The payee address to check
     * @param chequeData The cheque with signature to validate
     * @param signOverData Array of sign-over data (empty if no sign-overs)
     * @return True if the cheque is valid and payable to the payee
     */
    function isChequeValid(
        address payee,
        Cheque calldata chequeData,
        SignOver[] calldata signOverData
    ) external view returns (bool) {
        // 1.  Verify signature and compute chequeId from chequeData
        if (!_verifyChequeSignature(chequeData)) {
            return false;
        }

        // Verify timing (common check for all valid statuses)
        // Note: No need to check chain state because chequeId computation guarantees matching values
        if (block.timestamp < chequeData.chequeInfo.validFrom || 
            block.timestamp > chequeData.chequeInfo.validThru) {
            return false;
        }
        
        // Verify balance (common check for all valid statuses)
        if (balances[chequeData.chequeInfo.payer] < chequeData.chequeInfo.amount) {
            return false;
        }
        
        bytes32 chequeId = _computeChequeId(chequeData.chequeInfo);
        // Read cheque state from chain
        ChequeState memory chequeState = cheques[chequeId];
        
        // 2. If status is Revoked or Redeemed, return false
        if (chequeState.status == ChequeStatus.Revoked || 
            chequeState.status == ChequeStatus.Redeemed) {
            return false;
        }
        
        // 3. Unified logic for both None and Active status
        // Convention: signOverData must be a complete chain starting from chequeData.chequeInfo.payee
        // If no sign-over data provided, get current payee based on status
        if (signOverData.length == 0) {
            address currentPayee = chequeState.status == ChequeStatus.None 
                ? chequeData.chequeInfo.payee 
                : chequeState.payee;
            return payee == currentPayee;
        }
        
        // Check if sign-over chain length exceeds maximum (6)
        if (signOverData.length > 6) {
            return false;
        }
        
        // If status is Active, verify that signOverData has at least chequeState.signOverCount elements
        // and the current payee matches the sign-over chain at the corresponding index
        if (chequeState.status == ChequeStatus.Active) {
            // If sign-over data is shorter than on-chain count, return false
            if (signOverData.length < chequeState.signOverCount) {
                return false;
            }
            
            // If there are on-chain sign-overs, verify current payee matches
            if (chequeState.signOverCount > 0) {
                // The payee at index (signOverCount - 1) should match on-chain current payee
                if (signOverData[chequeState.signOverCount - 1].signOverInfo.newPayee != chequeState.payee) {
                    return false;
                }
            }
        }
        
        // Verify the complete sign-over chain starting from chequeData.chequeInfo.payee
        (bool isValid, address finalPayee) = _verifySignOverChainSegment(
            signOverData,
            chequeId,
            chequeData.chequeInfo.payee
        );
        
        // Return true only if chain is valid and final payee matches the expected payee
        return isValid && payee == finalPayee;
    }
    
}

