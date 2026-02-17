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
export declare const logEvent: (entry: AuditLogEntry) => Promise<void>;
//# sourceMappingURL=auditLogger.d.ts.map