pragma solidity ^0.8.20;

interface IChequeBank {
    // ============ EIP-712 Domain Separator ============
    // Domain name for EIP-712
    // This should be set in the contract implementation
    // string public constant DOMAIN_NAME = "ChequeBank";
    // string public constant DOMAIN_VERSION = "1";
    // bytes32 public constant DOMAIN_SEPARATOR = ...;

    // ============ EIP-712 Type Hashes ============
    // These constants should be defined in the contract implementation:
    // bytes32 public constant CHEQUE_INFO_TYPEHASH = keccak256(
    //     "ChequeInfo(uint256 amount,uint32 validFrom,uint32 validThru,uint32 nonce,address payee,address payer)"
    // );
    // bytes32 public constant SIGN_OVER_INFO_TYPEHASH = keccak256(
    //     "SignOverInfo(uint8 counter,address oldPayee,address newPayee,bytes32 chequeId)"
    // );

    struct ChequeInfo {
        uint256 amount;
        uint32 validFrom;
        uint32 validThru;
        uint32 nonce;  // Nonce to prevent chequeId collision
        address payee;
        address payer;
    }
    
    struct SignOverInfo {
        uint8 counter;
        address oldPayee;
        address newPayee;
        bytes32 chequeId;
    }

    struct Cheque {
        ChequeInfo chequeInfo;
        bytes sig;
    }
    
    struct SignOver {
        SignOverInfo signOverInfo;
        bytes sig;
    }

    // ============ Storage Optimization ============
    // Flattened struct containing both cheque info and state
    // payee: stores the current payee (updated on each sign-over)
    struct ChequeState {
        uint256 amount;          // 32 bytes
        uint32 validFrom;        // 4 bytes
        uint32 validThru;        // 4 bytes
        uint32 nonce;            // 4 bytes - Nonce to prevent chequeId collision
        address payee;           // 20 bytes - Current payee (updated on each sign-over)
        address payer;           // 20 bytes
        ChequeStatus status;     // 1 byte - ChequeStatus enum value
        uint8 signOverCount;     // 1 byte - number of sign-overs (max 6)
        // Storage layout (optimized packing):
        // Slot 0: amount (uint256) - 32 bytes
        // Slot 1: validFrom (uint32, 4) + validThru (uint32, 4) + nonce (uint32, 4) + payee (address, 20) = 32 bytes
        // Slot 2: payer (address, 20) + status (uint8, 1) + signOverCount (uint8, 1) = 22 bytes
        // Total: 3 storage slots (optimized packing)
    }
    // Note: In implementation, use: mapping(bytes32 => ChequeState) public cheques;

    enum ChequeStatus {
        None,      // 0 - Cheque doesn't exist
        Active,    // 1 - Cheque is active and can be redeemed
        Revoked,   // 2 - Cheque has been revoked by payer
        Redeemed   // 3 - Cheque has been redeemed
    }

    function deposit() payable external;
    function withdraw(uint amount, address payable recipient) external;
    
    // Activate a cheque (verify signature, store info, set status to Active)
    function active(Cheque calldata chequeData) external;
    
    // Redeem a cheque (only chequeId needed, reads from storage)
    function redeem(bytes32 chequeId) external;
    
    // Revoke a cheque (only chequeId needed)
    function revoke(bytes32 chequeId) external;
    
    // Notify sign-over (only SignOver needed, reads cheque info from storage)
    function notifySignOver(SignOver calldata signOverData) external;
    
    // Batch operations (atomic: all succeed or all revert)
    function multicall(bytes[] calldata data) 
        external 
        returns (bytes[] memory results);
    
    // View functions
    function getBalance(address account) external view returns (uint256);
    function getCheque(bytes32 chequeId) external view returns (ChequeState memory);
    
    // Check if a cheque is valid (optional view function)
    function isChequeValid(
        address payee,
        Cheque calldata chequeData,
        SignOver[] calldata signOverData
    ) external view returns (bool);
}