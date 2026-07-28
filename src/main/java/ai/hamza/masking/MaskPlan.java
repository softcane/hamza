package ai.hamza.masking;

import ai.hamza.adapter.ReplacementEdit;

import java.util.List;

/** Validated Adapter edits for one complete SOURCE Turn. */
public record MaskPlan(List<ReplacementEdit> edits, int maskedValueCount) {

    public MaskPlan {
        edits = edits == null ? List.of() : List.copyOf(edits);
        if (maskedValueCount < 0 || maskedValueCount != edits.size()) {
            throw new IllegalArgumentException("invalid masked-value count");
        }
    }
}
