package ai.hamza.attest;

import ai.hamza.persistence.RecoveryOutcome;

import java.time.Instant;

/** Raw content-free Recovery Outcome row used for independent verification. */
public record RecoveryOutcomeRow(
        long seq, String hashVersion, String prevHash, String entryHash,
        String recoveryId, String status, String agent, String agentVersion,
        String workflowProfileId, int workflowProfileVersion,
        String acceptanceGateId, String startedAt, String completedAt,
        String signatureVersion, String signature) {

    public RecordHasher.RecoveryOutcomeHashFields hashable() {
        return new RecordHasher.RecoveryOutcomeHashFields(
                recoveryId, status, agent, agentVersion, workflowProfileId,
                workflowProfileVersion, acceptanceGateId, startedAt, completedAt,
                signatureVersion, signature);
    }

    public RecoveryOutcome outcome() {
        return new RecoveryOutcome(new RecoveryOutcome.Unsigned(
                recoveryId, RecoveryOutcome.Status.fromWireValue(status), agent, agentVersion,
                workflowProfileId, workflowProfileVersion, acceptanceGateId,
                Instant.parse(startedAt), Instant.parse(completedAt)),
                signatureVersion, signature);
    }

    @Override
    public String toString() {
        return "RecoveryOutcomeRow[seq=" + seq + ", status=" + status + "]";
    }
}
