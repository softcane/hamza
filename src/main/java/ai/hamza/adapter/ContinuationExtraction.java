package ai.hamza.adapter;

import java.util.Objects;

/** Result of extracting transient continuation content from one Provider request. */
public sealed interface ContinuationExtraction
        permits ContinuationExtraction.Valid, ContinuationExtraction.Malformed,
        ContinuationExtraction.Unsupported {

    record Valid(ContinuationView view) implements ContinuationExtraction {
        public Valid {
            Objects.requireNonNull(view, "view");
        }
    }

    record Malformed(ContinuationFailureReason reason) implements ContinuationExtraction {
        public Malformed {
            Objects.requireNonNull(reason, "reason");
        }
    }

    record Unsupported(ContinuationFailureReason reason) implements ContinuationExtraction {
        public Unsupported {
            Objects.requireNonNull(reason, "reason");
        }
    }
}
