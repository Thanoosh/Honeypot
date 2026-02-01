# core/event_bus.py

from typing import Callable, Dict, List, Any


class EventBus:
    """
    Simple in-memory event bus.
    Other modules can publish events and subscribe to them.
    """

    def __init__(self):
        self.subscribers: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}

    def subscribe(self, event_type: str, handler: Callable[[Dict[str, Any]], None]):
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(handler)

    def publish(self, event_type: str, event_data: Dict[str, Any]):
        handlers = self.subscribers.get(event_type, [])
        for handler in handlers:
            handler(event_data)
