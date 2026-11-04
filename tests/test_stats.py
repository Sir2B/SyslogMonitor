from syslog_monitor.stats import RateTracker, StatsSnapshot


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def test_rate_tracker_uses_counter_deltas_over_elapsed_time():
    clock = Clock()
    tracker = RateTracker(clock)
    assert tracker.update(StatsSnapshot()).received == 0

    clock.now += 2
    rates = tracker.update(StatsSnapshot(
        received=10, persisted=8, dropped_queue_full=1, dropped_write_error=1))
    assert rates.received == 5
    assert rates.persisted == 4
    assert rates.dropped == 1

    clock.now += 0.5
    rates = tracker.update(StatsSnapshot(
        received=13, persisted=10, dropped_queue_full=1, dropped_write_error=1))
    assert rates.received == 6
    assert rates.persisted == 4
    assert rates.dropped == 0


def test_rate_tracker_handles_counter_reset_and_nonpositive_elapsed_time():
    clock = Clock()
    tracker = RateTracker(clock)
    tracker.update(StatsSnapshot(received=20, persisted=15, dropped_queue_full=2))
    clock.now += 1
    assert tracker.update(StatsSnapshot(received=4, persisted=3, dropped_queue_full=0)).received == 0
    clock.now += 1
    assert tracker.update(StatsSnapshot(received=5, persisted=4)).persisted == 1
    clock.now -= 1
    assert tracker.update(StatsSnapshot(received=100)).received == 0


def test_tcp_framing_drops_are_included_in_the_drop_rate():
    clock = Clock()
    tracker = RateTracker(clock)
    tracker.update(StatsSnapshot())
    clock.now += 2
    assert tracker.update(StatsSnapshot(dropped_tcp_framing=4)).dropped == 2
