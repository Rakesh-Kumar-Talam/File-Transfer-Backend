"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.logEvent = void 0;
const database_1 = require("../config/database");
/**
 * Log a system event for audit purposes
 */
const logEvent = async (entry) => {
    try {
        const db = (0, database_1.getDatabase)();
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
    }
    catch (error) {
        console.error('❌ Failed to write audit log:', error);
        // We don't throw here to avoid failing the actual request if logging fails,
        // although in highly regulated systems you might want to.
    }
};
exports.logEvent = logEvent;
//# sourceMappingURL=auditLogger.js.map