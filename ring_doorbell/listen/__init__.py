"""Package for listener modules."""

try:
    from .eventlistener import RingEventListener
    from .listenerconfig import RingEventListenerConfig

    can_listen = True
except ImportError:  # pragma: no cover
    can_listen = False  # pylint:disable=invalid-name

__all__ = [
    "RingEventListener",
    "RingEventListenerConfig",
]
