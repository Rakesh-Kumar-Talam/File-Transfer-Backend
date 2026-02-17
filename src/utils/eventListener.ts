import { ethers } from 'ethers';
import { getDatabase } from '../config/database';

/**
 * Basic Blockchain Event Listener to prevent state drift
 * Listens for FileUploaded events and ensures they are recorded in MongoDB
 */
export const initEventListener = async () => {
    const rpcUrl = process.env.POLYGON_RPC_URL;
    const contractAddress = process.env.VITE_CONTRACT_ADDRESS;

    if (!rpcUrl || !contractAddress) {
        console.warn('⚠️ Blockchain listener not started: Missing RPC URL or Contract Address');
        return;
    }

    try {
        const provider = new ethers.JsonRpcProvider(rpcUrl);
        const abi = [
            "event FileUploaded(bytes32 indexed fileId, address indexed sender, string ipfsCID, uint256 expiryTimestamp, uint256 maxAccess)"
        ];
        const contract = new ethers.Contract(contractAddress, abi, provider);

        console.log('📡 Starting blockchain event listener...');

        contract.on('FileUploaded', async (fileId, sender, ipfsCID, expiryTimestamp, maxAccess, event) => {
            console.log(`🔔 Event Received: FileUploaded - ${fileId}`);

            const db = getDatabase();

            // Check if file already exists in DB
            const existingFile = await db.collection('files').findOne({ ipfsCID });

            if (!existingFile) {
                console.log(`💾 Syncing file ${ipfsCID} from blockchain to DB...`);
                // Note: Some metadata (name, size, type) won't be available from chain
                // In a production system, we might fetch this from IPFS or a side-channel
                await db.collection('files').updateOne(
                    { ipfsCID },
                    {
                        $setOnInsert: {
                            fileId: fileId,
                            onChainId: event.log.transactionHash,
                            name: 'Restored from Chain',
                            size: 0,
                            type: 'unknown',
                            ipfsCID,
                            sender: 'unknown_sync', // We can't easily map address to userId here without a lookup
                            senderAddress: sender.toLowerCase(),
                            policy: {
                                expiryTimestamp: Number(expiryTimestamp) * 1000,
                                maxAccess: Number(maxAccess),
                                usedAccess: 0,
                            },
                            status: 'active',
                            createdAt: new Date(),
                            syncedFromChain: true
                        }
                    },
                    { upsert: true }
                );
            }
        });

    } catch (error) {
        console.error('❌ Failed to initialize blockchain listener:', error);
    }
};
