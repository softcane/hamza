package ai.hamza.adapter;

import java.util.Objects;

/** Result of applying decoded replacement edits to one Provider request. */
public sealed interface ContinuationTransformation
        permits ContinuationTransformation.Success, ContinuationTransformation.Failure {

    final class Success implements ContinuationTransformation {
        private final byte[] body;

        Success(byte[] body) {
            this.body = Objects.requireNonNull(body, "body").clone();
        }

        public byte[] body() {
            return body.clone();
        }

        @Override
        public String toString() {
            return "ContinuationTransformation.Success[bytes=" + body.length + "]";
        }
    }

    record Failure(ContinuationFailureReason reason) implements ContinuationTransformation {
        public Failure {
            Objects.requireNonNull(reason, "reason");
        }
    }
}
