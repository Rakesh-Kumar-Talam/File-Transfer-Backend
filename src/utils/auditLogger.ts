import { getDatabase } from '../config/database';

export type ActorRole = 'user' | 'admin' | 'guest' | 'sender' | 'receiver';
export type ActorType = 'wallet' | 'email' | 'admin' | 'system';
export type TargetType = 'user' | 'file' | 'auth' | 'system';
export type ActionStatus = 'success' | 'failure';

export interface AuditLogEntry {
    actorId: string;
    actorRole: ActorRole;
    actorType: ActorType;
    actionType: string;
    targetType: TargetType;
    targetId?: string;
    metadata?: any;
    ipAddress?: string;
    userAgent?: string;
    status: ActionStatus;
    createdAt?: Date;
}

/**
 * Log a system event for audit purposes
 */
export const logEvent = async (entry: AuditLogEntry) => {
    try {
        const db = getDatabase();
        const fullEntry = {
            ...entry,
            createdAt: new Date(),
        };

        // Ensure we don't log sensitive info in metadata
        if (fullEntry.metadata) {
            delete fullEntry.metadata.password;
            delete fullEntry.metadata.token;
            delete fullEntry.metadata.wrappedKey;
        }

        await db.collection('audit_logs').insertOne(fullEntry);
        console.log(`[AUDIT] ${entry.actorRole} ${entry.actionType} on ${entry.targetType} - ${entry.status}`);
    } catch (error) {
        console.error('❌ Failed to write audit log:', error);
        // We don't throw here to avoid failing the actual request if logging fails,
        // although in highly regulated systems you might want to.
    }
};
