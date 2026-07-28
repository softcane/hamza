package ai.hamza.continuation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class QuarantineBudgetTest {

    @Test
    void admissionReservesBeforeTheBodyAndReleasesExactlyOnce() {
        QuarantineBudget budget = new QuarantineBudget(new ByteCount(8), new ByteCount(12), 2);

        QuarantineAdmission first = budget.tryReserve(new ByteCount(7));
        QuarantineAdmission second = budget.tryReserve(new ByteCount(5));

        assertThat(first).isInstanceOf(QuarantineAdmission.Reserved.class);
        assertThat(second).isInstanceOf(QuarantineAdmission.Reserved.class);
        assertThat(budget.reservedBytes().value()).isEqualTo(12);
        ((QuarantineAdmission.Reserved) first).reservation().close();
        ((QuarantineAdmission.Reserved) first).reservation().close();
        assertThat(budget.reservedBytes().value()).isEqualTo(5);
    }

    @Test
    void unknownLengthConservativelyReservesTheWholePerTurnBound() {
        QuarantineBudget budget = new QuarantineBudget(new ByteCount(8), new ByteCount(8), 1);

        QuarantineAdmission admission = budget.tryReserveUnknownLength();

        assertThat(admission).isInstanceOf(QuarantineAdmission.Reserved.class);
        QuarantineReservation reservation = ((QuarantineAdmission.Reserved) admission).reservation();
        assertThat(reservation.acceptActual(new ByteCount(8))).isTrue();
        assertThat(reservation.acceptActual(new ByteCount(9))).isFalse();
        reservation.close();
        assertThat(budget.available()).isTrue();
    }

    @Test
    void perTurnTotalAndConcurrencyLimitsDenyWithoutChangingState() {
        QuarantineBudget budget = new QuarantineBudget(new ByteCount(8), new ByteCount(10), 1);

        assertThat(budget.tryReserve(new ByteCount(9)))
                .isEqualTo(new QuarantineAdmission.Denied(QuarantineDenial.PER_TURN_LIMIT));
        QuarantineAdmission accepted = budget.tryReserve(new ByteCount(6));
        assertThat(accepted).isInstanceOf(QuarantineAdmission.Reserved.class);
        assertThat(budget.tryReserve(new ByteCount(1)))
                .isEqualTo(new QuarantineAdmission.Denied(QuarantineDenial.CONCURRENCY_LIMIT));
        assertThat(budget.reservedBytes()).isEqualTo(new ByteCount(6));

        ((QuarantineAdmission.Reserved) accepted).reservation().close();
        QuarantineAdmission total = budget.tryReserve(new ByteCount(8));
        assertThat(total).isInstanceOf(QuarantineAdmission.Reserved.class);
    }

    @Test
    void totalMemoryLimitIsIndependentOfThePerTurnLimit() {
        QuarantineBudget budget = new QuarantineBudget(new ByteCount(8), new ByteCount(10), 3);
        QuarantineAdmission first = budget.tryReserve(new ByteCount(6));

        assertThat(budget.tryReserve(new ByteCount(5)))
                .isEqualTo(new QuarantineAdmission.Denied(QuarantineDenial.TOTAL_MEMORY_LIMIT));

        ((QuarantineAdmission.Reserved) first).reservation().close();
    }
}
