package ai.hamza.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ContainerNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Shared parse and segment bookkeeping behind the two JSON Provider Adapters. */
final class JsonContinuationSupport {

    private JsonContinuationSupport() {
    }

    static void requireOnlyFields(ObjectNode object, Set<String> allowed) {
        var names = object.fieldNames();
        while (names.hasNext()) {
            if (!allowed.contains(names.next())) {
                throw unsupported();
            }
        }
    }

    static ContinuationExtraction extract(ObjectMapper mapper, String provider, byte[] body,
                                          Schema schema) {
        if (body == null || body.length == 0) {
            return new ContinuationExtraction.Malformed(ContinuationFailureReason.EMPTY_BODY);
        }
        try {
            JsonNode parsed = mapper.readTree(body);
            if (!(parsed instanceof ObjectNode root)) {
                return new ContinuationExtraction.Malformed(ContinuationFailureReason.INVALID_REQUEST);
            }
            SegmentCollector collector = new SegmentCollector();
            schema.collect(root, collector);
            List<ContentSegment> segments = collector.segments();
            if (segments.isEmpty()) {
                return new ContinuationExtraction.Unsupported(
                        ContinuationFailureReason.NO_CONTENT_SEGMENTS);
            }
            return new ContinuationExtraction.Valid(new ContinuationView(provider, body, segments));
        } catch (WireShapeException e) {
            return e.malformed
                    ? new ContinuationExtraction.Malformed(e.reason)
                    : new ContinuationExtraction.Unsupported(e.reason);
        } catch (Exception e) {
            return new ContinuationExtraction.Malformed(ContinuationFailureReason.MALFORMED_JSON);
        }
    }

    static ContinuationTransformation transform(ObjectMapper mapper, String provider,
                                                ContinuationView view,
                                                List<ReplacementEdit> edits,
                                                String fixedDirective,
                                                Schema schema,
                                                DirectiveWriter directiveWriter) {
        if (view == null || edits == null || fixedDirective == null) {
            return failure(ContinuationFailureReason.INVALID_VIEW);
        }
        if (!provider.equals(view.provider())) {
            return failure(ContinuationFailureReason.WRONG_ADAPTER);
        }
        if (fixedDirective.length() > 4096 || fixedDirective.indexOf('\0') >= 0) {
            return failure(ContinuationFailureReason.INVALID_DIRECTIVE);
        }
        if (edits.isEmpty()) {
            return failure(ContinuationFailureReason.EMPTY_EDITS);
        }

        try {
            Document document = parseDocument(mapper, view.originalBodyCopy(), schema);
            if (!sameSegments(document.bindings, view.segments())) {
                return failure(ContinuationFailureReason.INVALID_VIEW);
            }

            Validation validation = validateEdits(document.bindings, edits);
            if (validation.failure != null) {
                return failure(validation.failure);
            }
            applyEdits(document.bindings, validation.bySegment);
            if (!fixedDirective.isBlank()) {
                directiveWriter.write(document.root, fixedDirective);
            }

            // Exactly one serialization. The second parse validates the final Provider shape.
            byte[] transformed = mapper.writeValueAsBytes(document.root);
            Document reparsed = parseDocument(mapper, transformed, schema);
            if (reparsed.bindings.isEmpty()) {
                return failure(ContinuationFailureReason.TRANSFORMED_REQUEST_INVALID);
            }
            return new ContinuationTransformation.Success(transformed);
        } catch (Exception e) {
            return failure(ContinuationFailureReason.TRANSFORMED_REQUEST_INVALID);
        }
    }

    private static Document parseDocument(ObjectMapper mapper, byte[] body, Schema schema)
            throws Exception {
        JsonNode parsed = mapper.readTree(body);
        if (!(parsed instanceof ObjectNode root)) {
            throw malformed();
        }
        SegmentCollector collector = new SegmentCollector();
        schema.collect(root, collector);
        if (collector.bindings.isEmpty()) {
            throw new WireShapeException(false, ContinuationFailureReason.NO_CONTENT_SEGMENTS);
        }
        return new Document(root, List.copyOf(collector.bindings));
    }

    private static boolean sameSegments(List<SegmentBinding> bindings,
                                        List<ContentSegment> segments) {
        if (bindings.size() != segments.size()) {
            return false;
        }
        for (int i = 0; i < bindings.size(); i++) {
            SegmentBinding binding = bindings.get(i);
            ContentSegment segment = segments.get(i);
            if (!binding.id.equals(segment.id()) || !binding.text.equals(segment.text())) {
                return false;
            }
        }
        return true;
    }

    private static Validation validateEdits(List<SegmentBinding> bindings,
                                            List<ReplacementEdit> edits) {
        Map<String, SegmentBinding> known = new LinkedHashMap<>();
        bindings.forEach(binding -> known.put(binding.id, binding));
        Map<String, List<ReplacementEdit>> bySegment = new HashMap<>();
        Set<Range> covered = new HashSet<>();
        Set<String> originals = new HashSet<>();

        for (ReplacementEdit edit : edits) {
            SegmentBinding binding = known.get(edit.segmentId());
            if (binding == null) {
                return Validation.failed(ContinuationFailureReason.UNKNOWN_SEGMENT);
            }
            if (edit.end() > binding.text.length()
                    || splitsSurrogate(binding.text, edit.start())
                    || splitsSurrogate(binding.text, edit.end())) {
                return Validation.failed(ContinuationFailureReason.EDIT_OUT_OF_RANGE);
            }
            String original = binding.text.substring(edit.start(), edit.end());
            if (original.equals(edit.replacement())) {
                return Validation.failed(ContinuationFailureReason.MISSING_EDIT);
            }
            originals.add(original);
            bySegment.computeIfAbsent(edit.segmentId(), ignored -> new ArrayList<>()).add(edit);
            covered.add(new Range(edit.segmentId(), edit.start(), edit.end()));
        }

        for (List<ReplacementEdit> segmentEdits : bySegment.values()) {
            segmentEdits.sort(Comparator.comparingInt(ReplacementEdit::start));
            int previousEnd = -1;
            for (ReplacementEdit edit : segmentEdits) {
                if (edit.start() < previousEnd) {
                    return Validation.failed(ContinuationFailureReason.OVERLAPPING_EDITS);
                }
                previousEnd = edit.end();
            }
        }

        // If a declared protected value repeats in any approved segment, every occurrence
        // must have its own exact edit. An entirely undeclared value is caught by the Gate's
        // mandatory complete final scan outside this Adapter interface.
        for (String original : originals) {
            for (SegmentBinding binding : bindings) {
                int from = 0;
                while (from <= binding.text.length() - original.length()) {
                    int start = binding.text.indexOf(original, from);
                    if (start < 0) {
                        break;
                    }
                    if (!covered.contains(new Range(binding.id, start, start + original.length()))) {
                        return Validation.failed(ContinuationFailureReason.MISSING_EDIT);
                    }
                    from = start + Math.max(1, original.length());
                }
            }
        }
        return new Validation(bySegment, null);
    }

    private static boolean splitsSurrogate(String text, int offset) {
        return offset > 0 && offset < text.length()
                && Character.isHighSurrogate(text.charAt(offset - 1))
                && Character.isLowSurrogate(text.charAt(offset));
    }

    private static void applyEdits(List<SegmentBinding> bindings,
                                   Map<String, List<ReplacementEdit>> bySegment) {
        for (SegmentBinding binding : bindings) {
            List<ReplacementEdit> edits = bySegment.get(binding.id);
            if (edits == null) {
                continue;
            }
            StringBuilder transformed = new StringBuilder(binding.text);
            for (int i = edits.size() - 1; i >= 0; i--) {
                ReplacementEdit edit = edits.get(i);
                transformed.replace(edit.start(), edit.end(), edit.replacement());
            }
            binding.setText(transformed.toString());
        }
    }

    private static ContinuationTransformation.Failure failure(
            ContinuationFailureReason reason) {
        return new ContinuationTransformation.Failure(reason);
    }

    @FunctionalInterface
    interface Schema {
        void collect(ObjectNode root, SegmentCollector collector);
    }

    @FunctionalInterface
    interface DirectiveWriter {
        void write(ObjectNode root, String directive);
    }

    static final class SegmentCollector {
        private final List<SegmentBinding> bindings = new ArrayList<>();

        void add(ObjectNode parent, String field) {
            JsonNode value = parent.get(field);
            if (value == null || !value.isTextual()) {
                throw unsupported();
            }
            add(value.textValue(), parent, field, -1);
        }

        void add(ArrayNode parent, int index) {
            JsonNode value = parent.get(index);
            if (value == null || !value.isTextual()) {
                throw unsupported();
            }
            add(value.textValue(), parent, null, index);
        }

        /** Add every decoded string value below one approved tool-content subtree. */
        void addTree(JsonNode node) {
            if (node instanceof ObjectNode object) {
                for (var field : object.properties()) {
                    if (field.getValue().isTextual()) {
                        add(object, field.getKey());
                    } else if (field.getValue().isContainerNode()) {
                        addTree(field.getValue());
                    }
                }
            } else if (node instanceof ArrayNode array) {
                for (int i = 0; i < array.size(); i++) {
                    JsonNode value = array.get(i);
                    if (value.isTextual()) {
                        add(array, i);
                    } else if (value.isContainerNode()) {
                        addTree(value);
                    }
                }
            }
        }

        private void add(String text, ContainerNode<?> parent, String field, int index) {
            bindings.add(new SegmentBinding("segment-" + bindings.size(), text,
                    parent, field, index));
        }

        List<ContentSegment> segments() {
            return bindings.stream()
                    .map(binding -> new ContentSegment(binding.id, binding.text))
                    .toList();
        }
    }

    private static final class SegmentBinding {
        private final String id;
        private final String text;
        private final ContainerNode<?> parent;
        private final String field;
        private final int index;

        private SegmentBinding(String id, String text, ContainerNode<?> parent,
                               String field, int index) {
            this.id = id;
            this.text = text;
            this.parent = parent;
            this.field = field;
            this.index = index;
        }

        private void setText(String replacement) {
            if (parent instanceof ObjectNode object) {
                object.put(field, replacement);
            } else if (parent instanceof ArrayNode array) {
                array.set(index, TextNode.valueOf(replacement));
            } else {
                throw new IllegalStateException("unsupported content container");
            }
        }
    }

    private record Document(ObjectNode root, List<SegmentBinding> bindings) {
    }

    private record Range(String segmentId, int start, int end) {
    }

    private record Validation(Map<String, List<ReplacementEdit>> bySegment,
                              ContinuationFailureReason failure) {
        private static Validation failed(ContinuationFailureReason reason) {
            return new Validation(Map.of(), reason);
        }
    }

    static WireShapeException malformed() {
        return new WireShapeException(true, ContinuationFailureReason.INVALID_REQUEST);
    }

    static WireShapeException unsupported() {
        return new WireShapeException(false, ContinuationFailureReason.UNSUPPORTED_CONTENT);
    }

    static final class WireShapeException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private final boolean malformed;
        private final ContinuationFailureReason reason;

        private WireShapeException(boolean malformed, ContinuationFailureReason reason) {
            super(reason.name(), null, false, false);
            this.malformed = malformed;
            this.reason = reason;
        }
    }
}
