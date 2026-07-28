package ai.hamza.persistence;

import ai.hamza.masking.MaskContinuationService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;

/** Signed, content-free append surface for terminal managed-Agent task evidence. */
@RestController
@RequestMapping("/admin/recovery-outcomes")
@ConditionalOnProperty(prefix = "hamza.continuation", name = "enabled", havingValue = "true")
public final class RecoveryOutcomeController {

    private final RecoveryOutcomeRepository repository;
    private final MaskContinuationService maskContinuation;

    public RecoveryOutcomeController(RecoveryOutcomeRepository repository,
                                     MaskContinuationService maskContinuation) {
        this.repository = java.util.Objects.requireNonNull(repository, "repository");
        this.maskContinuation = java.util.Objects.requireNonNull(maskContinuation,
                "maskContinuation");
    }

    @PostMapping(consumes = "application/json", produces = "application/json")
    public ResponseEntity<Receipt> append(@RequestBody Request request) {
        RecoveryOutcome outcome = request.toOutcome();
        RecoveryOutcomeAppendReceipt appended = repository.append(outcome);
        if (appended.disposition()
                == RecoveryOutcomeAppendReceipt.Disposition.CONFLICT_REJECTED) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Receipt.from(appended));
        }
        maskContinuation.closeScope(outcome.evidence().recoveryId());
        HttpStatus status = appended.disposition()
                == RecoveryOutcomeAppendReceipt.Disposition.APPENDED
                ? HttpStatus.CREATED : HttpStatus.OK;
        return ResponseEntity.status(status).body(Receipt.from(appended));
    }

    @ExceptionHandler(RecoveryOutcomeRejectedException.class)
    public ResponseEntity<Map<String, String>> rejected(RecoveryOutcomeRejectedException error) {
        HttpStatus status = error.reason()
                == RecoveryOutcomeRejectedException.Reason.INVALID_SIGNATURE
                ? HttpStatus.FORBIDDEN : HttpStatus.CONFLICT;
        String code = error.reason()
                == RecoveryOutcomeRejectedException.Reason.INVALID_SIGNATURE
                ? "invalid-outcome" : "invalid-outcome-link";
        return ResponseEntity.status(status).body(Map.of("error", code));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> malformed(IllegalArgumentException ignored) {
        return ResponseEntity.badRequest().body(Map.of("error", "invalid-outcome"));
    }

    public record Request(
            String recoveryId,
            String status,
            String agent,
            String agentVersion,
            String workflowProfileId,
            int workflowProfileVersion,
            String acceptanceGateId,
            String startedAt,
            String completedAt,
            String signatureVersion,
            String signature) {

        RecoveryOutcome toOutcome() {
            var evidence = new RecoveryOutcome.Unsigned(
                    recoveryId, RecoveryOutcome.Status.fromWireValue(status), agent, agentVersion,
                    workflowProfileId, workflowProfileVersion, acceptanceGateId,
                    Instant.parse(startedAt), Instant.parse(completedAt));
            return new RecoveryOutcome(evidence, signatureVersion, signature);
        }
    }

    public record Receipt(String disposition, long sequence, String entryHash) {
        static Receipt from(RecoveryOutcomeAppendReceipt receipt) {
            return new Receipt(receipt.disposition().name().toLowerCase(Locale.ROOT),
                    receipt.sequence(), receipt.entryHash());
        }
    }
}
