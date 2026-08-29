"""Tests for RansomEye CompositeCollector."""

from typing import Any
import pytest
from ransomeye.collectors.base import BaseCollector, CollectorState
from ransomeye.collectors.composite import CompositeCollector


class FakeCollector(BaseCollector):
    def __init__(self, name: str = "FakeCollector", should_fail: bool = False):
        super().__init__(name=name)
        self.should_fail = should_fail
        self.on_event = None

    def start(self) -> None:
        if self.should_fail:
            self.state = CollectorState.ERROR
            self.error_message = "Simulated failure"
            raise RuntimeError("Collector initialization failed")
        self.state = CollectorState.RUNNING

    def stop(self) -> None:
        self.state = CollectorState.STOPPED

    def collect(self):
        return []

    def emit_event(self, data: dict[str, Any]) -> None:
        self.events_collected += 1
        self.events_accepted += 1
        if self.on_event:
            self.on_event(data)


def test_composite_collector_lifecycle():
    c1 = FakeCollector(name="Child1")
    c2 = FakeCollector(name="Child2")

    composite = CompositeCollector(collectors=[c1, c2], name="TestComposite")
    assert composite.state == CollectorState.STOPPED
    assert len(composite.collectors) == 2

    composite.start()
    assert composite.state == CollectorState.RUNNING
    assert c1.state == CollectorState.RUNNING
    assert c2.state == CollectorState.RUNNING

    composite.stop()
    assert composite.state == CollectorState.STOPPED
    assert c1.state == CollectorState.STOPPED
    assert c2.state == CollectorState.STOPPED


def test_composite_event_routing_and_status():
    received_events = []

    def handle_event(event: dict[str, Any]):
        received_events.append(event)

    c1 = FakeCollector(name="Child1")
    c2 = FakeCollector(name="Child2")

    composite = CompositeCollector(
        collectors=[c1, c2],
        on_event=handle_event,
        name="RoutingComposite",
    )
    composite.start()

    c1.emit_event({"id": "evt-1", "source": "child1"})
    c2.emit_event({"id": "evt-2", "source": "child2"})

    assert len(received_events) == 2
    assert received_events[0]["id"] == "evt-1"
    assert received_events[1]["id"] == "evt-2"

    status = composite.status()
    assert status["name"] == "RoutingComposite"
    assert status["state"] == "RUNNING"
    assert status["events_collected"] == 2
    assert status["events_accepted"] == 2
    assert "Child1" in status["collectors"]
    assert "Child2" in status["collectors"]

    composite.stop()


def test_composite_fault_isolation_partial_failure():
    c_good = FakeCollector(name="GoodCollector", should_fail=False)
    c_bad = FakeCollector(name="BadCollector", should_fail=True)

    composite = CompositeCollector(collectors=[c_good, c_bad])
    composite.start()

    # Fault isolation: Good collector continues running even if Bad collector failed
    assert c_good.state == CollectorState.RUNNING
    assert c_bad.state == CollectorState.ERROR
    assert composite.state == CollectorState.RUNNING

    status = composite.status()
    assert status["collectors"]["GoodCollector"]["state"] == "RUNNING"
    assert status["collectors"]["BadCollector"]["state"] == "ERROR"

    composite.stop()
    assert c_good.state == CollectorState.STOPPED


def test_composite_all_failed():
    c_bad1 = FakeCollector(name="Bad1", should_fail=True)
    c_bad2 = FakeCollector(name="Bad2", should_fail=True)

    composite = CompositeCollector(collectors=[c_bad1, c_bad2])
    composite.start()

    assert composite.state == CollectorState.ERROR
    assert "All child collectors failed" in composite.error_message
    composite.stop()


def test_composite_get_and_add_collector():
    composite = CompositeCollector()
    c1 = FakeCollector(name="DynamicChild")

    composite.add_collector(c1)
    assert composite.get_collector("DynamicChild") is c1
    assert composite.get_collector("NonExistent") is None
    assert composite.collect() == []
