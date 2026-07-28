package ai.hamza.masking;

/** Bounded Placeholder families allowed on Provider Egress. */
public enum PlaceholderFamily {
    SECRET,
    ACCOUNT,
    EMAIL,
    PHONE,
    PERSON,
    LOCATION,
    IP,
    PII;

    String render(long identifier) {
        return '<' + name() + '_' + identifier + '>';
    }
}
