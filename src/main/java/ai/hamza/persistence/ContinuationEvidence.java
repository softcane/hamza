package ai.hamza.persistence;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Content-free linkage and accounting for a Safe Continuation Turn Record.
 * Protected values, Fingerprints, field ids, substitutes, and mappings are deliberately
 * absent from this interface.
 */
public record ContinuationEvidence(
        Role role,
        String recoveryId,
        String parentTurnId,
        String recipeId,
        Integer recipeVersion,
        String workflowProfileId,
        Integer workflowProfileVersion,
        Status continuationStatus,
        String reasonCode,
        String taskPath,
        TaskStatus taskStatus,
        Long requestBytesWithheld,
        Integer maskedValueCount) {

    private static final Pattern BOUNDED_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");

    public enum Role { STANDARD, SOURCE, DERIVED }

    public enum Status { ATTEMPTED, DELIVERED }

    public enum TaskStatus { UNVERIFIED }

    public ContinuationEvidence {
        role = Objects.requireNonNull(role, "role");
        if (role == Role.STANDARD) {
            requireAbsent(recoveryId, parentTurnId, recipeId, recipeVersion,
                    workflowProfileId, workflowProfileVersion, continuationStatus,
                    reasonCode, taskPath, taskStatus, requestBytesWithheld, maskedValueCount);
        } else {
            recoveryId = bounded(recoveryId, "recoveryId");
            continuationStatus = Objects.requireNonNull(continuationStatus, "continuationStatus");
            taskStatus = Objects.requireNonNull(taskStatus, "taskStatus");
            if (role == Role.SOURCE) {
                if (parentTurnId != null) {
                    throw new IllegalArgumentException("a source Record cannot have a parent Turn");
                }
                recipeId = bounded(recipeId, "recipeId");
                workflowProfileId = bounded(workflowProfileId, "workflowProfileId");
                positive(recipeVersion, "recipeVersion");
                positive(workflowProfileVersion, "workflowProfileVersion");
                reasonCode = bounded(reasonCode, "reasonCode");
                taskPath = bounded(taskPath, "taskPath");
                if (continuationStatus != Status.ATTEMPTED) {
                    throw new IllegalArgumentException("a source Record must be ATTEMPTED");
                }
                if (requestBytesWithheld == null || requestBytesWithheld < 0) {
                    throw new IllegalArgumentException("source withheld bytes must be non-negative");
                }
                if (maskedValueCount == null || maskedValueCount < 0) {
                    throw new IllegalArgumentException("source masked-value count must be non-negative");
                }
            } else {
                parentTurnId = bounded(parentTurnId, "parentTurnId");
                requireAbsent(recipeId, recipeVersion, workflowProfileId,
                        workflowProfileVersion, reasonCode, taskPath, requestBytesWithheld,
                        maskedValueCount);
                if (continuationStatus != Status.DELIVERED) {
                    throw new IllegalArgumentException("a derived Record must be DELIVERED");
                }
            }
        }
    }

    public static ContinuationEvidence none() {
        return new ContinuationEvidence(Role.STANDARD, null, null, null, null,
                null, null, null, null, null, null, null, null);
    }

    public static ContinuationEvidence source(String recoveryId, String recipeId,
                                              int recipeVersion, String workflowProfileId,
                                              int workflowProfileVersion, String taskPath,
                                              String reasonCode, long requestBytesWithheld) {
        return new ContinuationEvidence(Role.SOURCE, recoveryId, null, recipeId, recipeVersion,
                workflowProfileId, workflowProfileVersion, Status.ATTEMPTED, reasonCode,
                taskPath, TaskStatus.UNVERIFIED, requestBytesWithheld, 0);
    }

    public static ContinuationEvidence maskedSource(
            String recoveryId, String recipeId, int recipeVersion,
            String workflowProfileId, int workflowProfileVersion, String taskPath,
            String reasonCode, long requestBytesWithheld, int maskedValueCount) {
        if (maskedValueCount <= 0) {
            throw new IllegalArgumentException("masked source count must be positive");
        }
        return new ContinuationEvidence(Role.SOURCE, recoveryId, null, recipeId, recipeVersion,
                workflowProfileId, workflowProfileVersion, Status.ATTEMPTED, reasonCode,
                taskPath, TaskStatus.UNVERIFIED, requestBytesWithheld, maskedValueCount);
    }

    public static ContinuationEvidence derived(String recoveryId, String parentTurnId) {
        return new ContinuationEvidence(Role.DERIVED, recoveryId, parentTurnId, null, null,
                null, null, Status.DELIVERED, null, null, TaskStatus.UNVERIFIED, null, null);
    }

    static ContinuationEvidence restore(String role, String recoveryId, String parentTurnId,
                                        String recipeId, Integer recipeVersion,
                                        String workflowProfileId, Integer workflowProfileVersion,
                                        String continuationStatus, String reasonCode, String taskPath,
                                        String taskStatus, Long requestBytesWithheld,
                                        Integer maskedValueCount) {
        Role restoredRole = role == null ? Role.STANDARD : Role.valueOf(role);
        if (restoredRole == Role.STANDARD) {
            return none();
        }
        return new ContinuationEvidence(restoredRole, recoveryId, parentTurnId, recipeId,
                recipeVersion, workflowProfileId, workflowProfileVersion,
                Status.valueOf(continuationStatus), reasonCode, taskPath,
                TaskStatus.valueOf(taskStatus), requestBytesWithheld, maskedValueCount);
    }

    @Override
    public String toString() {
        return "ContinuationEvidence[role=" + role + ", continuationStatus="
                + continuationStatus + ", taskStatus=" + taskStatus + "]";
    }

    private static String bounded(String value, String field) {
        if (value == null || !BOUNDED_ID.matcher(value).matches()) {
            throw new IllegalArgumentException(field + " must be a bounded internal id");
        }
        return value;
    }

    private static void positive(Integer value, String field) {
        if (value == null || value <= 0) {
            throw new IllegalArgumentException(field + " must be positive");
        }
    }

    private static void requireAbsent(Object... values) {
        for (Object value : values) {
            if (value != null) {
                throw new IllegalArgumentException("field is not valid for this Record role");
            }
        }
    }
}
