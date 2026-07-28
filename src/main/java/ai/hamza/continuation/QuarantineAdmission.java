package ai.hamza.continuation;

import java.util.Objects;

/** Admission result for one fully quarantined managed Turn. */
public sealed interface QuarantineAdmission
        permits QuarantineAdmission.Reserved, QuarantineAdmission.Denied {

    record Reserved(QuarantineReservation reservation) implements QuarantineAdmission {
        public Reserved {
            reservation = Objects.requireNonNull(reservation, "reservation");
        }
    }

    record Denied(QuarantineDenial reason) implements QuarantineAdmission {
        public Denied {
            reason = Objects.requireNonNull(reason, "reason");
        }
    }
}
