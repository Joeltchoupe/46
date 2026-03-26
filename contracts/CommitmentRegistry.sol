// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title W46 CommitmentRegistry
 * @notice On-chain anchor for W46 proof Merkle roots.
 * 
 * Each batch of settled transactions produces a Merkle root.
 * That root is published here for permanent, tamper-evident storage.
 * 
 * Anyone can verify that a specific transaction was included in a batch
 * by providing a Merkle proof against the stored root.
 * 
 * Deployed on Base (Ethereum L2).
 */

contract CommitmentRegistry {

    // ── Events ────────────────────────────────────────────
    
    event RootCommitted(
        bytes32 indexed root,
        uint256 indexed batchIndex,
        uint256 txCount,
        uint256 timestamp,
        address indexed committer
    );

    event CommitterAdded(address indexed committer, address indexed addedBy);
    event CommitterRemoved(address indexed committer, address indexed removedBy);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ── State ─────────────────────────────────────────────

    struct Commitment {
        bytes32 root;
        uint256 txCount;
        uint256 timestamp;
        address committer;
    }

    address public owner;
    mapping(address => bool) public authorizedCommitters;
    
    Commitment[] public commitments;
    mapping(bytes32 => uint256) public rootToIndex;  // root => index+1 (0 means not found)
    
    uint256 public totalTransactionsAnchored;

    // ── Modifiers ─────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "CommitmentRegistry: not owner");
        _;
    }

    modifier onlyCommitter() {
        require(
            authorizedCommitters[msg.sender] || msg.sender == owner,
            "CommitmentRegistry: not authorized"
        );
        _;
    }

    // ── Constructor ───────────────────────────────────────

    constructor() {
        owner = msg.sender;
        authorizedCommitters[msg.sender] = true;
        emit CommitterAdded(msg.sender, msg.sender);
    }

    // ── Core Functions ────────────────────────────────────

    /**
     * @notice Commit a Merkle root representing a batch of W46 transactions.
     * @param root The Merkle root hash
     * @param txCount Number of transactions in this batch
     */
    function commitRoot(bytes32 root, uint256 txCount) external onlyCommitter {
        require(root != bytes32(0), "CommitmentRegistry: empty root");
        require(txCount > 0, "CommitmentRegistry: empty batch");
        require(rootToIndex[root] == 0, "CommitmentRegistry: root already committed");

        uint256 index = commitments.length;

        commitments.push(Commitment({
            root: root,
            txCount: txCount,
            timestamp: block.timestamp,
            committer: msg.sender
        }));

        rootToIndex[root] = index + 1;  // +1 so that 0 means "not found"
        totalTransactionsAnchored += txCount;

        emit RootCommitted(root, index, txCount, block.timestamp, msg.sender);
    }

    /**
     * @notice Verify that a Merkle root has been committed.
     * @param root The root to check
     * @return exists Whether the root has been committed
     * @return batchIndex The index of the commitment (if exists)
     * @return timestamp When it was committed
     */
    function verifyRoot(bytes32 root) external view returns (
        bool exists,
        uint256 batchIndex,
        uint256 timestamp
    ) {
        uint256 stored = rootToIndex[root];
        if (stored == 0) {
            return (false, 0, 0);
        }
        uint256 idx = stored - 1;
        return (true, idx, commitments[idx].timestamp);
    }

    /**
     * @notice Verify a Merkle proof for a leaf against a committed root.
     * @param root The committed Merkle root
     * @param leaf The leaf hash (transaction proof hash)
     * @param proof Array of sibling hashes
     * @param index Position of the leaf in the tree
     * @return valid Whether the proof is valid and root is committed
     */
    function verifyProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof,
        uint256 index
    ) external view returns (bool valid) {
        // First check root is committed
        if (rootToIndex[root] == 0) {
            return false;
        }

        // Verify Merkle proof
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (index % 2 == 0) {
                computedHash = keccak256(abi.encodePacked(computedHash, proof[i]));
            } else {
                computedHash = keccak256(abi.encodePacked(proof[i], computedHash));
            }
            index = index / 2;
        }

        return computedHash == root;
    }

    // ── View Functions ────────────────────────────────────

    /**
     * @notice Get the total number of commitments.
     */
    function getCommitmentCount() external view returns (uint256) {
        return commitments.length;
    }

    /**
     * @notice Get commitment details by index.
     */
    function getCommitment(uint256 index) external view returns (
        bytes32 root,
        uint256 txCount,
        uint256 timestamp,
        address committer
    ) {
        require(index < commitments.length, "CommitmentRegistry: index out of bounds");
        Commitment storage c = commitments[index];
        return (c.root, c.txCount, c.timestamp, c.committer);
    }

    /**
     * @notice Get the latest commitment.
     */
    function getLatestCommitment() external view returns (
        bytes32 root,
        uint256 txCount,
        uint256 timestamp,
        uint256 index
    ) {
        require(commitments.length > 0, "CommitmentRegistry: no commitments");
        uint256 idx = commitments.length - 1;
        Commitment storage c = commitments[idx];
        return (c.root, c.txCount, c.timestamp, idx);
    }

    // ── Admin Functions ───────────────────────────────────

    function addCommitter(address committer) external onlyOwner {
        require(committer != address(0), "CommitmentRegistry: zero address");
        authorizedCommitters[committer] = true;
        emit CommitterAdded(committer, msg.sender);
    }

    function removeCommitter(address committer) external onlyOwner {
        require(committer != owner, "CommitmentRegistry: cannot remove owner");
        authorizedCommitters[committer] = false;
        emit CommitterRemoved(committer, msg.sender);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "CommitmentRegistry: zero address");
        authorizedCommitters[newOwner] = true;
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
